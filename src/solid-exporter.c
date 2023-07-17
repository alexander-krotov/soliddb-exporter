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

#define _XOPEN_SOURCE 700 /* For -std=c99 compatibility. */

#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <pthread.h>

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

/* Older versions of libmicrohttpd do not define enum MHD_Result. */
#if MHD_VERSION <= 0x00093300
typedef int MHD_Result;
#else
typedef enum MHD_Result MHD_Result;
#endif

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

/* @brief SolidDb Pmon descriptor.
 *
 * That is our descriptor for the SolidDb pmon.
 * When initializing the exporter we provide the pmon short names and
 * their types, and then we read the longer description and the
 * position from the server.
 */
typedef struct {
	/* Pmon name we want to show to Prometheus. */
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
 * Create and initialize pmons array.
 *
 * @param name0 first pmon name
 *
 * @return NULL-terminated array of pmon pointers.
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
 * @param pmons pmons array
 */
void solid_pmons_free(SolidPmon **pmons)
{
	int i;
	for (i=0; pmons[i] != NULL; i++) {
		free(pmons[i]->pmon_short);
		free(pmons[i]->pmon_long);
		free(pmons[i]);
	}
	free(pmons);
}

/**
 * Compare 2 pmons by the names.
 *
 * The predicate to be used with qsort and bsearch.
 */
static int cmp_pmon_name(const void *m1, const void *m2)
{
	const SolidPmon *const *mi1 = m1;
	const SolidPmon *const *mi2 = m2;
	return strcmp((*mi1)->pmon_short, (*mi2)->pmon_short);
}

/**
 * Compare 2 pmons by the numbers.
 *
 * The predicate to be used with qsort and bsearch.
 */
static int cmp_pmon_no(const void *m1, const void *m2)
{
	const SolidPmon *const *mi1 = m1;
	const SolidPmon *const *mi2 = m2;
	if ((*mi1)->pmon_no < (*mi2)->pmon_no) {
		return -1;
	} else if ((*mi1)->pmon_no > (*mi2)->pmon_no) {
		return 1;
	} else {
		return 0;
	}
}

/**
 * Process one "pmon list" line.
 *
 * @param pmons pmons array
 * @param pmon_list_buffer one line from pmon list output
 * @param pmon_no line number
 * @param total_pmons total number of the pmons in pmons array
 *
 */
void solid_pmon_process_list_line(SolidPmon **pmons, char *pmon_list_buffer, int pmon_no, int total_pmons)
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
	SolidPmon key = { .pmon_short = pmon_list_buffer };
	SolidPmon *key_ptr = &key;
	SolidPmon **pmon_ptr = bsearch(&key_ptr, pmons, total_pmons, sizeof(pmons[0]), cmp_pmon_name);

	if (pmon_ptr == NULL) {
		/* Matching pmon not found. */
	} else if ((*pmon_ptr)->pmon_no != -1) {
		printf("duplicated pmon '%s'\n", pmon_list_buffer);
	} else {
		SolidPmon *pmon = *pmon_ptr;
		assert(strcmp(pmon->pmon_short, pmon_list_buffer) == 0);
		/* Save the number and longer description. */
		pmon->pmon_no = pmon_no;
		pmon->pmon_long = strdup(longer_desc);

		/* Convert short description to prometheus format. */
		char *short_desc = pmon->pmon_short;
		for (;*short_desc; short_desc++) {
			if (*short_desc == ' ') {
				*short_desc = '_';
			}
		}
	}
}

/**
 * Read the pmon descriptions from the server.
 *
 * @param pmons pmons array
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
	int total_pmons;
	int retcode = -1;  // Function return code.

	/* Initialize the unknown descriptions and pmon positions. */
	for (total_pmons=0; pmons[total_pmons] != NULL; total_pmons++) {
		pmons[total_pmons]->pmon_long = NULL;
		pmons[total_pmons]->pmon_no = -1;
	}

	/* Sort the pmons by pmon names. */
	qsort(pmons, total_pmons, sizeof(pmons[0]), cmp_pmon_name);

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

			/* Check if full description does fit into the buffer. */
			if (indicator >= sizeof(pmon_list_buffer)) {
				printf("pmon buffer overflow.\n");
				break;
			}

			/* Process description line. */
			solid_pmon_process_list_line(pmons, pmon_list_buffer, pmon_no, total_pmons);
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
		for (int i=0; pmons[i] !=NULL; i++) {
			if (pmons[i]->pmon_no == -1) {
				/* This pmon was not found. */
				printf("pmon not found: %s\n", pmons[i]->pmon_short);
				retcode = -1;
			}
		}
		qsort(pmons, total_pmons, sizeof(pmons[0]), cmp_pmon_no);
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

/**
 * Convert pmon type to string.
 *
 * @param pmon_type Pmon type
 *
 * @return statically allocated pmon type name.
 */
char *pmon_type_str(SolidPmonType pmon_type)
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
 * @param pmons pmons array
 * @param pmons_line "pmon -r" output line.
 *
 * @return malloc-allocated response text.
 */
char *solid_pmon_response_from_buffer(SolidPmon **pmons, char *pmon_r)
{
	int pmon_no; // pmon number in the string.
	char *ret = strdup(""); // Output string seed.
	int out_len = 0; // Output len
	int pos = 0;  // Current pmon number.

	while (pmons[pos]->pmon_no == -1) {
		pos++;
	}

	/* Go through the line of ' '-separated values. */
	for (pmon_no=0; pmon_r != NULL; pmon_no++) {
		/* Skip the whitespaces. */
		while (*pmon_r == ' ') {
			pmon_r++;
		}

		/* pmons array is already sorted by pmon_no. */
		if (pmons[pos]->pmon_no == pmon_no) {
			char *pmon_end = strchr(pmon_r, ' ');

			int pmon_len = pmon_end == NULL ? strlen(pmon_r): pmon_end-pmon_r;

			ret = realloc(ret, out_len+pmon_len+strlen(pmons[pos]->pmon_long)+
			                   3*strlen(pmons[pos]->pmon_short)+200);

			/* Write HELP, TYPE lines and counter name. */
			sprintf(ret+out_len,
			      "# HELP %s %s\n# TYPE %s %s\n%s ",
			      pmons[pos]->pmon_short, // HELP
			      pmons[pos]->pmon_long,
			      pmons[pos]->pmon_short, // TYPE
			      pmon_type_str(pmons[pos]->pmon_type),
			      pmons[pos]->pmon_short);
			out_len += strlen(ret+out_len);
			/* Append the pmon value. */
			strncpy(ret+out_len, pmon_r, pmon_len);
			out_len += pmon_len;
			ret[out_len++] = '\n';
			ret[out_len] = 0;

			/* Move to the next pmon in our list. */
			pos++;
			if (pmons[pos] == NULL) {
				/* We have run over all the interesting pmons. */
				break;
			}
			/* Assert the expected sorting order. */
			assert(pmons[pos]->pmon_no > pmon_no);
		}

		/* Get to the next pmon in the list. */
		pmon_r = strchr(pmon_r, ' ');
	}

	return ret;
}

/**
 * Create metrics output for pmons.
 *
 * @param pmons pmons array
 *
 * @return malloc-allocated response text.
 */
char *solid_pmons_metrics(SolidPmon **pmons)
{
	/* ODBC environment, connection and statement. */
	HENV henv = SQL_NULL_HENV;
	HDBC hdbc = SQL_NULL_HDBC;
	HSTMT hstmt = SQL_NULL_HSTMT;
	SQLRETURN r;
	char *ret = NULL;  /* Function return code. */

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
				/* Check if full description does fit into the buffer. */
				if (indicator >= buffer_size) {
					printf("pmon buffer overflow.\n");
					/* Make sure buffer is 0-terminated. */
					pmon_list_buffer[buffer_size-1] = 0;
				}
				ret = solid_pmon_response_from_buffer(pmons, pmon_list_buffer);
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
 * @return MHD_queue_response return code.
 */
MHD_Result solidhttp_handler(
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

	/* Create a response. */
	assert(buf != NULL);
	struct MHD_Response *response = MHD_create_response_from_buffer(strlen(buf), (void *)buf, must_copy);
	MHD_Result ret;
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
		solid_connect_password = argv[4];
	}
}

static pthread_cond_t done = PTHREAD_COND_INITIALIZER;

/**
 * Signal handler for the signals interrupting the daemon.
 *
 * It does nothing but sends the main function a message (done)
 * and that makes the main function exit.
 *
 * @param signal - not used
 */
void intHandler(int signal) {
	int rc;
	printf("shutting down.\n");
	rc = pthread_cond_signal(&done);
	assert(rc == 0);
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
		/* Start http daemon. */
		daemon = MHD_start_daemon(flags, port, NULL, NULL, &solidhttp_handler, pmons, MHD_OPTION_END);
		if (daemon == NULL) {
			printf("Cannot start MHD daemon\n");
			ret = 1;
		}
	}

	if (ret == 0) {
		ret = pthread_cond_init(&done, NULL);
	}

	if (ret == 0) {
		/* Our main waiting loop. It is only interrupted by sending INT or STOP signal. */
		signal(SIGINT, intHandler);
		signal(SIGSTOP, intHandler);

		/* Wait for done message to be sent. */
		int rc;
		pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
		do {
			rc = pthread_cond_wait(&done, &mutex);
		} while (rc != 0);
		pthread_cond_destroy(&done);
		pthread_mutex_destroy(&mutex);
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
