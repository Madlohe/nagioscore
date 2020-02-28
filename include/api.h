#ifndef API_H_INCLUDED
#define API_H_INCLUDED

typedef struct nagiosapi_options {
	int   port;
	char *private_key_file;
	char *certificate_file;
	char *token;
} nagiosapi_options;


extern nagiosapi_options nagiosapi_api_options;

int nagiosapi_start_api_server();
int nagiosapi_stop_api_server();

#endif