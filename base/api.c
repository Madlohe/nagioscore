#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <microhttpd.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "../include/cJSON.h"
#include "../include/api.h"
#include "../include/logging.h"

struct MHD_Daemon *nagiosapi_http_daemon = NULL;
nagiosapi_options nagiosapi_api_options = { .port = 0, .private_key_file = NULL, .certificate_file = NULL, .token = NULL };

static long
nagiosapi_get_file_size (const char *filename)
{
  FILE *fp;

  fp = fopen (filename, "rb");
  if (fp)
    {
      long size;

      if ((0 != fseek (fp, 0, SEEK_END)) || (-1 == (size = ftell (fp))))
        size = 0;

      fclose (fp);

      return size;
    }
  else
    return 0;
}

static char *
nagiosapi_load_file (const char *filename)
{
  FILE *fp;
  char *buffer;
  long size;

  size = nagiosapi_get_file_size (filename);
  if (0 == size)
    return NULL;

  fp = fopen (filename, "rb");
  if (! fp)
    return NULL;

  buffer = malloc (size + 1);
  if (! buffer)
    {
      fclose (fp);
      return NULL;
    }
  buffer[size] = '\0';

  if (size != (long)fread (buffer, 1, size, fp))
    {
      free (buffer);
      buffer = NULL;
    }

  fclose (fp);
  return buffer;
}

int
nagiosapi_error_response( struct MHD_Connection *connection, 
        int error_code, 
        const char *error_message, 
        int data_type )
{
    struct MHD_Response *response = MHD_create_response_from_buffer(
        strlen(error_message), 
        (void *)error_message, 
        data_type
    );

    int ret = MHD_queue_response(connection, error_code, response);
    MHD_destroy_response(response);
    return ret;
}

/* Takes raw post data and returns a json-encoded string that can be passed off to the user */
char *
nagiosapi_process_transaction(const char *upload_data) {
    cJSON *result = cJSON_CreateObject();
    cJSON_AddItemToObjectCS(result, "status", cJSON_CreateString("acknowledged"));
    cJSON_AddItemToObjectCS(result, "uuid", cJSON_CreateString("8d41e80a-0e00-41a2-b2c4-764936e2f0fc"));

    char* result_str = cJSON_Print(result);

    cJSON_Delete(result);
    return result_str;
}

int 
nagiosapi_answer_to_connection (void *cls, struct MHD_Connection *connection,
                const char *url,
                const char *method,
                const char *version,
                const char *upload_data,
                size_t *upload_data_size, void **con_cls)
{

    struct MHD_Response *response;
    int ret;
    nagiosapi_options options = *((nagiosapi_options *) cls);

    const char *err_method = "<html><body>Invalid method - only POST is supported</body></html>";
    const char *err_token = "<html><body>Invalid token</body></html>";
    const char *client_token = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "token");

    if (client_token == NULL || (strcmp(client_token, options.token) != 0)) {
        response = MHD_create_response_from_buffer (strlen (err_token),
                                    (void *) err_token,
                                    MHD_RESPMEM_PERSISTENT);

        ret = MHD_queue_response (connection, MHD_HTTP_UNAUTHORIZED, response);
        MHD_destroy_response(response);
        return ret;
    }

    if (strncmp(method, "POST", 4) != 0) {
        response = MHD_create_response_from_buffer (strlen (err_method),
                                    (void *) err_method,
                                    MHD_RESPMEM_PERSISTENT);

        ret = MHD_queue_response (connection, MHD_HTTP_METHOD_NOT_ALLOWED, response);
        MHD_destroy_response(response);
        return ret;
    }

    char *transaction_result = nagiosapi_process_transaction(upload_data);

    response = MHD_create_response_from_buffer (strlen (transaction_result),
                                (void *) transaction_result,
                                MHD_RESPMEM_MUST_COPY);

    free(transaction_result);

    ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
    MHD_destroy_response(response);

    return ret;
}

int 
nagiosapi_start_api_server(nagiosapi_options options)
{
	logit(NSLOG_INFO_MESSAGE, FALSE, "Starting nagios API server\n");
    char *key_pem, *cert_pem;

    if ((options.private_key_file == NULL) || (options.certificate_file == NULL)) {
        logit(NSLOG_RUNTIME_ERROR, TRUE, "The nagios API was not given a key/cert pair.\n"
        	"The HTTP daemon will not be started.\n");
        return 1;
    }

    key_pem = nagiosapi_load_file (options.private_key_file);
    cert_pem = nagiosapi_load_file (options.certificate_file);

    if ((key_pem == NULL) || (cert_pem == NULL)) {
        logit(NSLOG_RUNTIME_ERROR, TRUE, "The nagios API was not given a valid key/cert pair.\n"
        	"The HTTP daemon will not be started.\n");
        return 1;
    }

    if (options.port < 1 || options.port > 65535) {
    	logit(NSLOG_RUNTIME_ERROR, TRUE, "The nagios API was given an invalid TCP port.\n"
    		"The HTTP daemon will not be started.\n");
    	return 1;
    }

    if (options.token == NULL || strlen(options.token) == 0) {
    	logit(NSLOG_RUNTIME_ERROR, TRUE, "The nagios API was given a zero-length token.\n"
    		"The HTTP daemon will not be started.\n");
    	return 1;
    }

    nagiosapi_http_daemon = MHD_start_daemon (MHD_USE_INTERNAL_POLLING_THREAD | MHD_USE_TLS,
                options.port, NULL, NULL, 
                &nagiosapi_answer_to_connection, &options,
                MHD_OPTION_HTTPS_MEM_KEY, key_pem,
                MHD_OPTION_HTTPS_MEM_CERT, cert_pem,
                MHD_OPTION_END);

    if (nagiosapi_http_daemon == NULL) {

    	logit(NSLOG_RUNTIME_ERROR, TRUE, "The nagios API HTTP daemon was not able to start\n");

        free (key_pem);
        free (cert_pem);
        return 1;
    }

    return 0;
}

int 
nagiosapi_stop_api_server()
{
	MHD_stop_daemon(nagiosapi_http_daemon);
	return 0;
}
