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

#include "microhttpd.h"
#include "solidodbc3.h"

#define LISTEN_PORT 9101
#define SOLIDDB_CONNECT_STRING "tcp 1964"
#define SOLIDDB_USER_NAME "dba"
#define SOLIDDB_PASSWORD "dba"
#define MAX_PMON_DESC_LIST 200

static unsigned short port = LISTEN_PORT;
static char *solid_connect_string = SOLIDDB_CONNECT_STRING;
static char *solid_connect_user = SOLIDDB_USER_NAME;
static char *solid_connect_password = SOLIDDB_PASSWORD;

/* Type of the Pmon counter */
typedef enum {
 	/* PmonCounter corresponds to Counter
 	 * https://prometheus.io/docs/concepts/metric_types/#counter
	 */
	PmonCounter,

 	/* Pmon value corresponds to Prometeus Gauge
 	 * https://prometheus.io/docs/concepts/metric_types/#gauge
	 */
	PmonValue
} SolidPmonType;

/* @brief SolidDb Pmon descriptopr.
 *
 * That is our descriptor for the SolidDb pmon.
 * When initializing the exporter we provide the pmon short names and
 * therir types, and then we read the longer description and the
 * positon from the server.
 */
typedef struct {
	/* Pmon name we want tp show to Prometheus. */
	char *pmon_short;

	/* Pmon type. We cannot derive it from the Solid pmon output,
	 * so it should be known in the exporter.
	 */
	SolidPmonType pmon_type;

	/* Pmon long description. We read it from SolidDb server. */
	char *pmon_long;

	/* Pmon value position in the SolidDb pmon output. */
	int pmon_no;
} SolidPmon;

/**
 * Create and initiaize pmons array. 
 *
 * @param name0 first ppmon name
 *
 * @return NULL-terminnated array of pmon pointers.
 */
SolidPmon **solid_pmons_init(char *name0, ...)
{
	int n = 0; // Number of pmons read.
	char *name = name0;
	SolidPmon **pmons = malloc(sizeof(SolidPmon*));
	va_list ap;

	pmons[0] = NULL;

	va_start(ap, name0);

	while (name != NULL) {
		/* Get the next pmon type from the parameters. */
		SolidPmonType type = va_arg(ap, SolidPmonType);

		/* Create new pmon. */
		SolidPmon *pmon = malloc(sizeof(SolidPmon));
		pmon->pmon_short = strdup(name);
		pmon->pmon_type = type;
		pmon->pmon_long = NULL;
		pmon->pmon_no = -1;

		/* Push new pmon to the pmons array. */
		pmons = realloc(pmons, (n+2)*sizeof(SolidPmon*));
		pmons[n] = pmon;
		pmons[n+1] = NULL;
		n++;

		/* Take the next pmon name from the parameters. */
		name = va_arg(ap, char*);
	}

	return pmons;
}

/**
 * Deallocate the pmons array.
 *
 * @param ppmons pmons array
 */
void solid_pmons_free(SolidPmon **pmons)
{
	int i;
	for (i=0; pmons[i] !=NULL; i++) {
		free(pmons[i]->pmon_short);
		free(pmons[i]->pmon_long);
		free(pmons[i]);
	}
	free(pmons);
}

/**
 * Process one "pmon list" line.
 *
 * @param ppmons pmons array
 * @param pmon_list_buffer one line from pmon list output
 * @param pmon_no line number
 *
 */
void solid_pmon_process_list_line(SolidPmon **pmons, char *pmon_list_buffer, int pmon_no)
{
	/* pmon_list_buffer now has short description and
	 * long description, separated by comma.
	 */
	char *longer_desc = strchr(pmon_list_buffer, ',');
	if (longer_desc != NULL) {
		/* We found the separator: terminate the
		 * short decription at comma and move
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
	 *
	 * We are using linear seach here for simplicity.
	 * If needed it could be optimized to use hasing.
	 */
	int i;
	for (i=0; pmons[i] !=NULL; i++) {
		if (strcmp(pmon_list_buffer, pmons[i]->pmon_short) == 0) {
			if (pmons[i]->pmon_no != -1) {
				printf("duplicted pmon '%s'\n", pmon_list_buffer);
				break;
			}
			/* Save the number and longer description. */
			pmons[i]->pmon_no = pmon_no;
			pmons[i]->pmon_long = strdup(longer_desc);

			/* Conver short description to prometeus format. */
			char *short_desc = pmons[i]->pmon_short;
			for (;*short_desc; short_desc++) {
				if (*short_desc == ' ') {
					*short_desc = '_';
				}
			}
		}
	}
}

/**
 * Read the pmon descriptions from the server.
 *
 * @param ppmons pmons array
 *
 * @return 0 if success.
 */
int solid_pmons_read_desc(SolidPmon **pmons)
{
	/* ODBC environment, connection and statement. */
	HENV henv = SQL_NULL_HENV; 
	HDBC hdbc = SQL_NULL_HDBC;
	HSTMT hstmt = SQL_NULL_HSTMT;
	SQLRETURN r;
	int i;
	int retcode = -1;  // Function return code.

	/* Initilize the unknownlog descriptins and pmon positions. */
	for (i=0; pmons[i] != NULL; i++) {
		pmons[i]->pmon_long = NULL;
		pmons[i]->pmon_no = -1;
	}

	/* Allocate the environment and connection handles. */
	r = SQLAllocEnv(&henv);
	assert(r == SQL_SUCCESS);
	r = SQLAllocConnect(henv, &hdbc);
	assert(r == SQL_SUCCESS);

	/* Connect to the server. */
	r = SQLConnect(
                hdbc,
                solid_connect_string, SQL_NTS,
                solid_connect_user, SQL_NTS,
                solid_connect_password, SQL_NTS);

	if (r == SQL_SUCCESS || r == SQL_SUCCESS_WITH_INFO) {
		int pmon_no; /* pmon number. */

		r = SQLAllocStmt(hdbc, &hstmt);
		assert(r == SQL_SUCCESS);

		/* Execute an admin command that prints the pmon descriptors. */
		r = SQLExecDirect(hstmt, "admin command 'pmon list'", SQL_NTS);

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

			/* Check if full descriptin does fit into the buffer. */
			if (indicator >= sizeof(pmon_list_buffer)) {
				printf("pmon buffer overflow.\n");
				break;
			}

			/* Process description line. */
			solid_pmon_process_list_line(pmons, pmon_list_buffer, pmon_no);
		}
	}

	if (r == SQL_ERROR) {
		/* Handle the error and print error message. */
		UCHAR   szSqlState[6];
		UCHAR   szErrorMsg[128];
		SDWORD  naterr;
		SWORD   length;
		SQLRETURN rc;

		rc = SQLError(henv, hdbc, hstmt,
                      szSqlState, &naterr, szErrorMsg, sizeof(szErrorMsg),
                      &length);
		assert(rc == SQL_SUCCESS);
		printf("ODBC error: %d: %s\n", naterr, szErrorMsg);
		retcode = -1;
	} else if (r == SQL_NO_DATA) {
		/* Assume success return. */
		retcode = 0;

		/* Check if all the pmons were found. */
		for (i=0; pmons[i] !=NULL; i++) {
			if (pmons[i]->pmon_no == -1) {
				/* This pmon was not found. */
				printf("pmon not found: %s\n", pmons[i]->pmon_short);
				retcode = -1;
			}
		}
	}

	/* Free the handles. */
	if (hstmt != SQL_NULL_HSTMT) {
		r = SQLFreeStmt(hstmt, SQL_DROP);
		assert(r == SQL_SUCCESS);
	}

	SQLDisconnect(hdbc);
	r = SQLFreeConnect(hdbc);
	assert(r == SQL_SUCCESS);
	r = SQLFreeEnv(henv);
	assert(r == SQL_SUCCESS);

	return retcode;
}


char *pmon_type_str(SolidPmonType pmon_type)
{
	switch (pmon_type) {
		case PmonCounter: return "couner";
		case PmonValue: return "gauge";
		default: assert(0); return NULL;
	}
}

/**
 * Create metrics output from "pmon -r" output line.
 *
 * line is ' ' separated list of pmon values.
 *
 * @param ppmons pmons array
 * @param pmons_line "pmon -r" output line.
 *
 * @return malloc-allocted responce text.
 */
char *solid_pmon_respoce_from_buffer(SolidPmon **pmons, char *pmon_r)
{
	int pmon_no; // pmon number in 
	char *ret = strdup(""); // Output string seed.
	int out_len = 0; // Output len

	/* Go through the line of ' '-separated values. */
	for (pmon_no=0; pmon_r != NULL; pmon_no++) {
		/* Skip the whitespaces. */
		while (*pmon_r == ' ') {
			pmon_r++;
		}

		/* Run through the pmons. */
		for (int i=0; pmons[i] != NULL; i++) {
			/* Check if want this pmon value in the output */
			if (pmons[i]->pmon_no == pmon_no) {
				char *pmon_end = strchr(pmon_r, ' ');

				int pmon_len = pmon_end == NULL ? strlen(pmon_r): pmon_end-pmon_r;

				ret = realloc(ret, out_len+pmon_len+strlen(pmons[i]->pmon_long)+
				                   3*strlen(pmons[i]->pmon_short)+200);

				/* Write HELP, TYPE lines and counter name. */
				sprintf(ret+out_len,
				      "# HELP %s %s\n# TYPE %s %s\n%s ",
				      pmons[i]->pmon_short, // HELP
				      pmons[i]->pmon_long,
				      pmons[i]->pmon_short, // TYPE
				      pmon_type_str(pmons[i]->pmon_type),
				      pmons[i]->pmon_short);
				out_len += strlen(ret+out_len);
				/* Append the pmon value. */
				strncpy(ret+out_len, pmon_r, pmon_len);
				out_len += pmon_len;
				ret[out_len++] = '\n';
				ret[out_len] = 0;
			}
		}

		/* Get to the next pmon in the list. */
		pmon_r = strchr(pmon_r, ' ');
	}

	return ret;
}

/**
 * Create metrics output for pmons.
 *
 * @param ppmons pmons array
 *
 * @return malloc-allocted responce text.
 */
char *solid_pmons_metrics(SolidPmon **pmons)
{
	/* ODBC environment, connection and statement. */
	HENV henv = SQL_NULL_HENV; 
	HDBC hdbc = SQL_NULL_HDBC;
	HSTMT hstmt = SQL_NULL_HSTMT;
	SQLRETURN r;
	char *ret = NULL;  /* Function reurn code. */

	/* Allocate the environment and connection handles. */
	r = SQLAllocEnv(&henv);
	assert(r == SQL_SUCCESS);
	r = SQLAllocConnect(henv, &hdbc);
	assert(r == SQL_SUCCESS);

	/* Connect to the server. */
	r = SQLConnect(
                hdbc,
                solid_connect_string, SQL_NTS,
                solid_connect_user, SQL_NTS,
                solid_connect_password, SQL_NTS);

	if (r == SQL_SUCCESS || r == SQL_SUCCESS_WITH_INFO) {
		r = SQLAllocStmt(hdbc, &hstmt);
		assert(r == SQL_SUCCESS);

		/* Execute an admin command that prints the pmon descriptors. */
		r = SQLExecDirect(hstmt, "admin command 'pmon -r'", SQL_NTS);

		r = SQLFetch(hstmt);
		if (r == SQL_SUCCESS) {
			/* Read the description to pmon_list_buffer. */
			SQLLEN indicator;
			int buffer_size = 100000;
			char *pmon_list_buffer = malloc(buffer_size);
			r = SQLGetData(hstmt, 2, SQL_C_CHAR,
                        	      	pmon_list_buffer, buffer_size,
                               		&indicator);

			if (r == SQL_SUCCESS) {
				/* Check if full descriptin does fit into the buffer. */
				if (indicator >= buffer_size) {
					printf("pmon buffer overflow.\n");
					/* Make sure buffer is 0-terminated. */
					pmon_list_buffer[buffer_size-1] = 0;
				}
				ret = solid_pmon_respoce_from_buffer(pmons, pmon_list_buffer);
			}
			free(pmon_list_buffer);
		} else if (r == SQL_NO_DATA) {
			ret = strdup("# ERROR: unexpected admin command output.\n");
		}
	}

	if (r == SQL_ERROR) {
		/* Handle the error and print error message. */
		UCHAR   szSqlState[6];
		UCHAR   szErrorMsg[128];
		SDWORD  naterr;
		SWORD   length;
		SQLRETURN rc;

		rc = SQLError(henv, hdbc, hstmt,
                      szSqlState, &naterr, szErrorMsg, sizeof(szErrorMsg),
                      &length);
		assert(rc == SQL_SUCCESS);
		printf("ODBC error: %d: %s\n", naterr, szErrorMsg);
		asprintf(&ret, "# ERROR: ODBC: %d: %s\n", naterr, szErrorMsg);
	}

	/* Free the handles. */
	if (hstmt != SQL_NULL_HSTMT) {
		r = SQLFreeStmt(hstmt, SQL_DROP);
		assert(r == SQL_SUCCESS);
	}

	SQLDisconnect(hdbc);
	r = SQLFreeConnect(hdbc);
	assert(r == SQL_SUCCESS);
	r = SQLFreeEnv(henv);
	assert(r == SQL_SUCCESS);

	return ret;
}

/**
 * Micohttpd callback: HTTP request handler.
 *
 * @param connection MHD connection
 * @param url URL string
 * @param method HTTP method string
 *
 * @return MHD_queue_response retunr code.
 */
enum MHD_Result solidhttp_handler(
	void *p, struct MHD_Connection *connection, const char *url, const char *method,
	const char *version, const char *upload_data, size_t *upload_data_size, void **con_cls)
{
	char *buf = NULL;
	int status_code = MHD_HTTP_BAD_REQUEST;
	SolidPmon **pmons = p;
	int must_copy = MHD_RESPMEM_PERSISTENT;

	/* Handle the method and url. */
	if (strcmp(method, "GET") != 0) {
		buf = "Invalid HTTP Method\n";
	} else if (strcmp(url, "/") == 0) {
		buf = "OK\n";
		status_code = MHD_HTTP_OK;
	} else if (strcmp(url, "/metrics") == 0) {
		/* Handle the real Prometheus request. */
		buf = solid_pmons_metrics(pmons);
		must_copy = MHD_RESPMEM_MUST_FREE;
		status_code = MHD_HTTP_OK;
	} else {
		buf = "Bad Request\n";
	}

	/* Create a responce. */
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

/**
 * Process command-line arguments: [port] [connect-string] [user] [password]
 */
void process_argv(int argc, char **argv)
{
	if (argc >= 2) {
		port = atoi(argv[1]);
	}

	if (argc >= 3) {
		solid_connect_string = argv[2];
	}

	if (argc >= 4) {
		solid_connect_user = argv[3];
	}

	if (argc >= 5) {
		solid_connect_password = argv[3];
	}
}

static int done = 0;

void intHandler(int signal) {
	printf("shutting down.\n");
	done = 1;
}

int main(int argc, char **argv)
{
	unsigned int flags = MHD_USE_SELECT_INTERNALLY;
	struct MHD_Daemon *daemon = NULL;  // Microhttpd daemon
	int ret = 0;  // return code.

	process_argv(argc, argv);

	/* Create the pmons container. */
	SolidPmon **pmons = solid_pmons_init(
			"Ru user CPU time used", PmonValue,
			"Mem size", PmonValue,
			"Db size", PmonValue,
			NULL
	);

	if (pmons != NULL) {
		ret = solid_pmons_read_desc(pmons);
	} else {
		ret = 1;
	}

	if (ret == 0) {
		/* Start http deaemon. */
		daemon = MHD_start_daemon(flags, port, NULL, NULL, &solidhttp_handler, pmons, MHD_OPTION_END);
		if (daemon == NULL) {
			printf("Cannot start MHD daemon\n");
			ret = 1;
		}
	}

	if (ret == 0) {
		/* Our main waiting loop. It is only interrupted by sending INT or STOP signal. */
		signal(SIGINT, intHandler);
		signal(SIGSTOP, intHandler);
		while(done == 0) {}
	}

	/* Free the httpd daemon. */
	if (daemon != NULL) {
		MHD_stop_daemon(daemon);
	}

	/* Free the pmons. */
	if (pmons != NULL) {
		solid_pmons_free(pmons);
	}

	return ret;
}
