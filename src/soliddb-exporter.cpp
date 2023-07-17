/**
 * Copyright 2022 Alexander Krotov.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <mcheck.h>

#include <vector>
#include <string>
#include <sstream>
#include <memory>
#include <iostream>
#include <condition_variable>
#include <algorithm>

extern "C" {
#include "microhttpd.h"
#include "solidodbc3.h"
}

#define LISTEN_PORT 9101
#define SOLIDDB_CONNECT_STRING "tcp 1964"
#define SOLIDDB_USER_NAME "dba"
#define SOLIDDB_PASSWORD "dba"
#define MAX_PMON_DESC_LIST 200

static unsigned short port = LISTEN_PORT;

/* Type of the Pmon counter */
typedef enum {
 	/* PmonCounter corresponds to Counter
 	 * https://prometheus.io/docs/concepts/metric_types/#counter
	 */
	PmonCounter,

 	/* Pmon value corresponds to Prometheus Gauge
 	 * https://prometheus.io/docs/concepts/metric_types/#gauge
	 */
	PmonValue
} SolidPmonType;

/* Our error type. Used to throw exceptions.
 *
 * It is intentionally made copy-costructable and not movable.
 */
class ExporterError {
 protected:
	char *error_text;

 public:
	ExporterError(const char *txt): error_text(strdup(txt)) {}
	ExporterError(const ExporterError &e): error_text(strdup(e.error_text)) {}
	~ExporterError() { free(error_text); }
	const char *get_error() const { return error_text; }
};

/* Specialized ODBC error type.
 *
 * It is intentionally made copy-costructable and not movable.
 */
class ODBCError: public ExporterError {
	int native_error;

 public:
	ODBCError(HENV henv, HDBC hdbc, HSTMT hstmt): ExporterError("")
	{
		/* Handle the error and copy the error message. */
		UCHAR   szSqlState[6];
		UCHAR   szErrorMsg[128];
		SDWORD  naterr;
		SWORD   length;
		SQLRETURN rc;

		rc = SQLError(henv, hdbc, hstmt,
                      szSqlState, &naterr, szErrorMsg, sizeof(szErrorMsg),
                      &length);
		assert(rc == SQL_SUCCESS);

		native_error = naterr;
		free(error_text);
		asprintf(&error_text, "Error %d: %s", native_error, error_text);
	}

	ODBCError(const ODBCError &e): ExporterError(e), native_error(e.native_error) {}
};

class SolidExporter {

	/* @brief SolidDb Pmon descriptor.
	 *
	 * That is our descriptor for the SolidDb pmon.
	 * When initializing the exporter we provide the pmon short names and
	 * their types, and then we read the longer description and the
	 * position from the server.
	 *
	 * SolidDb is movable.
	 */
	struct SolidPmon {
		// Pmon name we want to show to Prometheus.
		char *pmon_short;

		// Pmon type. We cannot derive it from the Solid pmon output,
		// so it should be known in the exporter.
		SolidPmonType pmon_type;

		// Pmon long description. We read it from SolidDb server.
		char *pmon_long;

		// Pmon value position in the SolidDb pmon output.
		int pmon_no;

		// Prometheus name
		char *prom_name;
	};

	int buffer_size = 100000;

	/* constant strings, not declared const explicitly for compatibility
	 * with the pure C functions we are using.
	 */
	char *solid_connect_string;   // SolidDb ODBC connect string.
	char *solid_connect_user;     // ODBC user name
	char *solid_connect_password; // ODBC password.

	// ODBC connection and environment handles
	HDBC hdbc;
	HENV henv;
	HSTMT hstmt;

	// Our pmons.
	std::vector<SolidPmon> pmons;

	// Flag saying we have read the descriptions and do not allow new pmons
	// to be added to the exporter.
	bool completed;

	void process_list_line(char *pmon_list_buffer, int pmon_no) noexcept;
	void connect();
	void disconnect() noexcept;
	static const char *pmon_type_str(SolidPmonType pmon_type);
	std::string response_from_buffer(const std::string &pmon_r);
	std::string get_pmon_metrics();

 public:
	// Create an exporter with given connect parameters.
	SolidExporter(const char *connect_string, const char *user, const char *password):
		solid_connect_string(strdup(connect_string)),
		solid_connect_user(strdup(user)),
		solid_connect_password(strdup(password)),
		henv(SQL_NULL_HENV),
		hdbc(SQL_NULL_HDBC),
		hstmt(SQL_NULL_HSTMT),
		completed(false)
	{
		assert(solid_connect_string);
		assert(solid_connect_user);
		assert(solid_connect_password);

		SQLRETURN r;
		r = SQLAllocEnv(&henv);
		assert(r == SQL_SUCCESS);
		r = SQLAllocConnect(henv, &hdbc);
		assert(r == SQL_SUCCESS);
	}

	// Deallocate the exporter.
	~SolidExporter() {
		free(solid_connect_string);
		free(solid_connect_user);
		free(solid_connect_password);

		for (auto i=pmons.begin(); i!=pmons.end(); ++i) {
			free(i->pmon_short);
			free(i->pmon_long);
			free(i->prom_name);
		}
	}

	/**
	 * Add new pmon to the exporter.
	 *
	 * @param pmon_name Name of SolidDb pmon.
	 * @param pmon_type Type of the pmon (could be Counter to Value)
 	 */
	void add_pmon(const char* pmon_name, SolidPmonType pmon_type)
	{
		SolidPmon p = { strdup(pmon_name), pmon_type, NULL, -1, NULL };
		pmons.push_back(p);
	}

	void read_desc();
	std::string pmons_metrics();
};

/**
 * Process one "pmon list" line.
 *
 * @param pmon_list_buffer one line from pmon list output
 * @param pmon_no line number
 *
 */
void SolidExporter::process_list_line(char *pmon_list_buffer, int pmon_no) noexcept
{
	/* pmon_list_buffer now has short description and
	 * long description, separated by comma.
	 */
	char *longer_desc = strchr(pmon_list_buffer, ',');
	if (longer_desc != NULL) {
		/* We found the separator: terminate the
		 * short description at comma and move
		 * longer description start to the next char.
		 */
		*longer_desc = 0;
		longer_desc++;
	} else {
		/* There is no longer description.
		 * Use the sort description instead.
		 */
		longer_desc = pmon_list_buffer;
	}

	/* We are trying to find the matching short description
	 * in pmons.
	 */
	auto pmon = std::lower_bound(pmons.begin(), pmons.end(), pmon_list_buffer,
		  [](const SolidPmon &a, const char *b) { return strcmp(a.pmon_short, b) < 0; }
	);

	if (pmon == pmons.end() || strcmp(pmon->pmon_short, pmon_list_buffer) != 0) {
		/* Not found. */
	} else if (pmon->pmon_no != -1) {
		printf("duplicated pmon '%s'\n", pmon_list_buffer);
	} else {
		/* Save the number and longer description. */
		pmon->pmon_no = pmon_no;
		pmon->pmon_long = strdup(longer_desc);
		pmon->prom_name = strdup(pmon->pmon_short);

		/* Convert short description to prometheus format. */
		char *prm_desc = pmon->prom_name;
		for (char *prm_name = pmon->prom_name; *prm_name; prm_name++) {
			if (*prm_name == ' ') {
				*prm_name = '_';
			}
		}
	}
}

/**
 * Connect to the server and create a new statement.
 *
 * In case of failure we throw an ODBCError exception.
 */
void SolidExporter::connect()
{
	/* Connect to the server. */
	SQLRETURN r = SQLConnect(
                hdbc,
                (SQLCHAR*)solid_connect_string, SQL_NTS,
                (SQLCHAR*)solid_connect_user, SQL_NTS,
                (SQLCHAR*)solid_connect_password, SQL_NTS);

	if (r == SQL_ERROR) {
		throw ODBCError(henv, hdbc, SQL_NULL_HSTMT);
	}

	assert(hstmt == SQL_NULL_HSTMT);

	r = SQLAllocStmt(hdbc, &hstmt);
	assert(r == SQL_SUCCESS);
}

/**
 * Disconnect from the server and free the statement.
 */
void SolidExporter::disconnect() noexcept
{
	if (hstmt != SQL_NULL_HSTMT) {
		SQLFreeStmt(hstmt, SQL_DROP);
		hstmt = SQL_NULL_HSTMT;
	}
	SQLDisconnect(hdbc);
}

/**
 * Read the pmon descriptions from the server.
 *
 * @return 0 if success.
 */
void SolidExporter::read_desc()
{
	int pmon_no; /* pmon number. */

	assert(!completed);

	connect();
	completed = true;  // We do not allow adding new pmons after that.

	// Sort the pmons by name.
	std::sort(pmons.begin(), pmons.end(),
		  [](const SolidPmon &a, const SolidPmon &b) { return strcmp(a.pmon_short, b.pmon_short) < 0; }
	);

	/* Execute an admin command that prints the pmon descriptors. */
	SQLRETURN r = SQLExecDirect(hstmt, (SQLCHAR*)"admin command 'pmon list'", SQL_NTS);

	for (pmon_no=0; r != SQL_ERROR; pmon_no++) {
		SQLLEN indicator;
		char pmon_list_buffer[MAX_PMON_DESC_LIST];

		r = SQLFetch(hstmt);
		if (r == SQL_ERROR || r == SQL_NO_DATA) {
			break;
		}

		/* Read the description to pmon_list_buffer. */
		r = SQLGetData(hstmt, 2, SQL_C_CHAR,
                             	pmon_list_buffer, sizeof(pmon_list_buffer),
                              	&indicator);
		if (r == SQL_ERROR) {
			break;
		}

		/* Check if full description does fit into the buffer. */
		if (indicator >= sizeof(pmon_list_buffer)) {
			printf("pmon buffer overflow.\n");
			break;
		}

		/* Process description line. */
		process_list_line(pmon_list_buffer, pmon_no);
	}

	if (r == SQL_ERROR) {
		throw ODBCError(henv, hdbc, hstmt);
	}
	
	assert(r == SQL_NO_DATA);
	/* Check if all the pmons were found. */
	for (auto i = pmons.begin(); i != pmons.end(); ++i) {
		if (i->pmon_no == -1) {
			/* This pmon was not found. */
			char *err_str;
			asprintf(&err_str, "pmon not found: %s", i->pmon_short);
			throw ExporterError(err_str);
		}
	}

	// Sort the pmons by pmon_no.
	std::sort(pmons.begin(), pmons.end(),
		  [](const SolidPmon &a, const SolidPmon &b) { return a.pmon_no < b.pmon_no; }
	);
}

/**
 * Convert pmon type to string.
 *
 * @param pmon_type Pmon type
 *
 * @return statically allocated pmon type name.
 */
const char *SolidExporter::pmon_type_str(SolidPmonType pmon_type)
{
	switch (pmon_type) {
		case PmonCounter: return "counter";
		case PmonValue: return "gauge";
		default: assert(0); return NULL;
	}
}

/**
 * Create metrics output from "pmon -r" output line.
 *
 * line is ' ' separated list of pmon values.
 *
 * @param pmon_r "pmon -r" output line.
 *
 * @return response text.
 */
std::string SolidExporter::response_from_buffer(const std::string &pmon_r)
{
	std::ostringstream output_buffer; // Where we collect the response text.
	int start = 0; // Pmon starting position.
	auto pos = pmons.begin();

	/* Skip the unknown pmons. */
	while (pos != pmons.end() && pos->pmon_no == -1) {
		++pos;
	}

	/* Go through the line of ' '-separated values. */
	for (int pmon_no=0; ; pmon_no++) {
		/* Skip the whitespaces. */
    		int pmon_end = pmon_r.find(' ', start);

		/* Check if want this pmon value in the output */
		if (pos->pmon_no == pmon_no) {
			/* Write HELP, TYPE lines. */
			output_buffer << "# HELP " << pos->prom_name << " " << pos->pmon_long << std::endl;
			output_buffer << "# TYPE " << pos->prom_name << " " << pmon_type_str(pos->pmon_type) << std::endl;
			output_buffer << pos->prom_name << " ";
			/* Append the pmon value. */
		        if (pmon_end != std::string::npos) {
		       		output_buffer << pmon_r.substr(start, pmon_end-start) << std::endl;
			} else {
		       		output_buffer << pmon_r.substr(start) << std::endl;
			}

			/* Move to the next pmon. */
			++pos;
			if (pos == pmons.end()) {
				break;
			}
		}

		/* Get to the next pmon in the list. */
		if (pmon_end == std::string::npos) {
			break;
		}
		start = pmon_end+1;  // Move start 1 char past ' ' delimiter.
	}

	return output_buffer.str();
}

/**
 * Create metrics output for pmons.
 *
 * @return response text.
 */
std::string SolidExporter::pmons_metrics()
{
	try {
		return get_pmon_metrics();
	} catch (const ODBCError &e) {
		// Ignore the error now.
		// We will reconnect.
	} catch (...) {
		assert(0);
	}

	try {
		disconnect();
		connect();
		return get_pmon_metrics();
	} catch (const ODBCError &e) {
		// Reconnect did not help.
		return std::string("# ")+e.get_error();
	} catch (...) {
		assert(0);
	}
	return "# FATAL error.";
}

/** Read the pmon values from the server by using admin command 'pmon -r'.
 *
 * @return response text.
 */
std::string SolidExporter::get_pmon_metrics()
{
	SQLRETURN r = SQLExecDirect(hstmt, (SQLCHAR*)"admin command 'pmon -r'", SQL_NTS);
	if (r == SQL_ERROR) {
		throw ODBCError(henv, hdbc, hstmt);
	}

	r = SQLFetch(hstmt);
	if (r == SQL_ERROR) {
		throw ODBCError(henv, hdbc, hstmt);
	}

	/* Read the description to pmon_list_buffer. */
	SQLLEN indicator;
	std::unique_ptr<char[]> pmon_list_buffer(new char [buffer_size]);
	r = SQLGetData(hstmt, 2, SQL_C_CHAR,
              	      	pmon_list_buffer.get(), buffer_size,
              		&indicator);
	if (r == SQL_ERROR) {
		throw ODBCError(henv, hdbc, hstmt);
	}

	/* Check if full description does fit into the buffer. */
	if (indicator >= buffer_size) {
		throw ExporterError("pmon buffer overflow.\n");
	}
	if (r == SQL_NO_DATA) {
		return "# ERROR: unexpected admin command output.\n";
	}
	/* Make sure buffer is 0-terminated. */
	pmon_list_buffer[buffer_size-1] = 0;

	return response_from_buffer(pmon_list_buffer.get());
}

/**
 * Micohttpd callback: HTTP request handler.
 *
 * @param connection MHD connection
 * @param url URL string
 * @param method HTTP method string
 *
 * @return MHD_queue_response return code.
 */
enum MHD_Result solidhttp_handler(
	void *p, struct MHD_Connection *connection, const char *url, const char *method,
	const char *version, const char *upload_data, size_t *upload_data_size, void **con_cls)
{
	const char *buf = NULL;
	int status_code = MHD_HTTP_BAD_REQUEST;
	SolidExporter *pmons = (SolidExporter *)p;
	MHD_ResponseMemoryMode must_copy = MHD_RESPMEM_PERSISTENT;

	/* Handle the method and url. */
	if (strcmp(method, "GET") != 0) {
		buf = "Invalid HTTP Method\n";
	} else if (strcmp(url, "/") == 0) {
		buf = "OK\n";
		status_code = MHD_HTTP_OK;
	} else if (strcmp(url, "/metrics") == 0) {
		/* Handle the real Prometheus request. */
		buf = strdup(pmons->pmons_metrics().c_str());
		must_copy = MHD_RESPMEM_MUST_FREE;
		status_code = MHD_HTTP_OK;
	} else {
		buf = "Bad Request\n";
	}

	/* Create a response. */
	assert(buf != NULL);
	struct MHD_Response *response = MHD_create_response_from_buffer(strlen(buf), (void *)buf, must_copy);
	enum MHD_Result ret;
	if (response) {
		ret = MHD_queue_response(connection, status_code, response);
		MHD_destroy_response(response);
	} else {
		ret = MHD_NO;
	}

	return ret;
}

std::condition_variable done;

/**
 * Signal handler for the signals interrupting our daemon.
 *
 * It does nothing but sends the main function message (done)
 * and that makes the main function exit.
 *
 * @param signal - not used
 */
void intHandler(int signal) {
	printf("shutting down.\n");
	done.notify_one();
}

int main(int argc, char **argv)
{
	unsigned int flags = MHD_USE_SELECT_INTERNALLY;
	int ret = 0;  // return code.
	const char *connect_string = SOLIDDB_CONNECT_STRING;
	const char *connect_user = SOLIDDB_USER_NAME;
	const char *connect_password = SOLIDDB_PASSWORD;

	// Process command-line arguments: [port] [connect-string] [user] [password]
	if (argc >= 2) {
		port = atoi(argv[1]);
	}
	if (argc >= 3) {
		connect_string = argv[2];
	}
	if (argc >= 4) {
		connect_user = argv[3];
	}
	if (argc >= 5) {
		connect_password = argv[4];
	}

	/* Create the pmons container. */
	SolidExporter pmons (connect_string, connect_user, connect_password);
	pmons.add_pmon("Ru user CPU time used", PmonValue);
	pmons.add_pmon("Mem size", PmonValue);
	pmons.add_pmon("Db size", PmonValue);

	try {
		pmons.read_desc();

		/* Start http daemon. */
		// Microhttpd daemon
		MHD_Daemon *daemon = MHD_start_daemon(flags, port, NULL, NULL, &solidhttp_handler, &pmons, MHD_OPTION_END);
		if (daemon == NULL) {
			printf("Cannot start MHD daemon\n");
			ret = 1;
		}

		/* Our main waiting loop. It is only interrupted by sending INT or STOP signal. */
		signal(SIGINT, intHandler);
		signal(SIGSTOP, intHandler);
		std::mutex m;
		std::unique_lock lm(m);
		done.wait(lm);

		/* Free the httpd daemon. */
		if (daemon != NULL) {
			MHD_stop_daemon(daemon);
		}
	} catch (const ExporterError &e) {
		std::cout << "Error: " << e.get_error();
	}

	return ret;
}
