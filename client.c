#include <libwebsockets.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "server.h"

#ifdef DEBUG
typedef struct {
	char* message;
	int reason;
} LWS_CALLBACK_MAP_ENTRY;

LWS_CALLBACK_MAP_ENTRY callbackMap[] = {
	{"LWS_CALLBACK_PROTOCOL_INIT", 27},
	{"LWS_CALLBACK_PROTOCOL_DESTROY", 28},
	{"LWS_CALLBACK_WSI_CREATE", 29},
	{"LWS_CALLBACK_WSI_DESTROY", 30},
	{"LWS_CALLBACK_WSI_TX_CREDIT_GET", 103},
	{"LWS_CALLBACK_OPENSSL_LOAD_EXTRA_CLIENT_VERIFY_CERTS", 21},
	{"LWS_CALLBACK_OPENSSL_LOAD_EXTRA_SERVER_VERIFY_CERTS", 22},
	{"LWS_CALLBACK_OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION", 23},
	{"LWS_CALLBACK_OPENSSL_CONTEXT_REQUIRES_PRIVATE_KEY", 37},
	{"LWS_CALLBACK_SSL_INFO", 67},
	{"LWS_CALLBACK_OPENSSL_PERFORM_SERVER_CERT_VERIFICATION", 58},
	{"LWS_CALLBACK_SERVER_NEW_CLIENT_INSTANTIATED", 19},
	{"LWS_CALLBACK_HTTP", 12},
	{"LWS_CALLBACK_HTTP_BODY", 13},
	{"LWS_CALLBACK_HTTP_BODY_COMPLETION", 14},
	{"LWS_CALLBACK_HTTP_FILE_COMPLETION", 15},
	{"LWS_CALLBACK_HTTP_WRITEABLE", 16},
	{"LWS_CALLBACK_CLOSED_HTTP",  5},
	{"LWS_CALLBACK_FILTER_HTTP_CONNECTION", 18},
	{"LWS_CALLBACK_ADD_HEADERS", 53},
	{"LWS_CALLBACK_VERIFY_BASIC_AUTHORIZATION", 102},
	{"LWS_CALLBACK_CHECK_ACCESS_RIGHTS", 51},
	{"LWS_CALLBACK_PROCESS_HTML", 52},
	{"LWS_CALLBACK_HTTP_BIND_PROTOCOL", 49},
	{"LWS_CALLBACK_HTTP_DROP_PROTOCOL", 50},
	{"LWS_CALLBACK_HTTP_CONFIRM_UPGRADE", 86},
	{"LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP", 44},
	{"LWS_CALLBACK_CLOSED_CLIENT_HTTP", 45},
	{"LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ", 48},
	{"LWS_CALLBACK_RECEIVE_CLIENT_HTTP", 46},
	{"LWS_CALLBACK_COMPLETED_CLIENT_HTTP", 47},
	{"LWS_CALLBACK_CLIENT_HTTP_WRITEABLE", 57},
	{"LWS_CALLBACK_CLIENT_HTTP_REDIRECT", 104},
	{"LWS_CALLBACK_CLIENT_HTTP_BIND_PROTOCOL", 85},
	{"LWS_CALLBACK_CLIENT_HTTP_DROP_PROTOCOL", 76},
	{"LWS_CALLBACK_ESTABLISHED",  0},
	{"LWS_CALLBACK_CLOSED",  4},
	{"LWS_CALLBACK_SERVER_WRITEABLE", 11},
	{"LWS_CALLBACK_RECEIVE",  6},
	{"LWS_CALLBACK_RECEIVE_PONG",  7},
	{"LWS_CALLBACK_WS_PEER_INITIATED_CLOSE", 38},
	{"LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION", 20},
	{"LWS_CALLBACK_CONFIRM_EXTENSION_OKAY", 25},
	{"LWS_CALLBACK_WS_SERVER_BIND_PROTOCOL", 77},
	{"LWS_CALLBACK_WS_SERVER_DROP_PROTOCOL", 78},
	{"LWS_CALLBACK_CLIENT_CONNECTION_ERROR",  1},
	{"LWS_CALLBACK_CLIENT_FILTER_PRE_ESTABLISH",  2},
	{"LWS_CALLBACK_CLIENT_ESTABLISHED",  3},
	{"LWS_CALLBACK_CLIENT_CLOSED", 75},
	{"LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER", 24},
	{"LWS_CALLBACK_CLIENT_RECEIVE",  8},
	{"LWS_CALLBACK_CLIENT_RECEIVE_PONG",  9},
	{"LWS_CALLBACK_CLIENT_WRITEABLE", 10},
	{"LWS_CALLBACK_CLIENT_CONFIRM_EXTENSION_SUPPORTED", 26},
	{"LWS_CALLBACK_WS_EXT_DEFAULTS", 39},
	{"LWS_CALLBACK_FILTER_NETWORK_CONNECTION", 17},
	{"LWS_CALLBACK_WS_CLIENT_BIND_PROTOCOL", 79},
	{"LWS_CALLBACK_WS_CLIENT_DROP_PROTOCOL", 80},
	{"LWS_CALLBACK_GET_THREAD_ID", 31},
	{"LWS_CALLBACK_ADD_POLL_FD", 32},
	{"LWS_CALLBACK_DEL_POLL_FD", 33},
	{"LWS_CALLBACK_CHANGE_MODE_POLL_FD", 34},
	{"LWS_CALLBACK_LOCK_POLL", 35},
	{"LWS_CALLBACK_UNLOCK_POLL", 36},
	{"LWS_CALLBACK_CGI", 40},
	{"LWS_CALLBACK_CGI_TERMINATED", 41},
	{"LWS_CALLBACK_CGI_STDIN_DATA", 42},
	{"LWS_CALLBACK_CGI_STDIN_COMPLETED", 43},
	{"LWS_CALLBACK_CGI_PROCESS_ATTACH", 70},
	{"LWS_CALLBACK_SESSION_INFO", 54},
	{"LWS_CALLBACK_GS_EVENT", 55},
	{"LWS_CALLBACK_HTTP_PMO", 56},
	{"LWS_CALLBACK_RAW_PROXY_CLI_RX", 89},
	{"LWS_CALLBACK_RAW_PROXY_SRV_RX", 90},
	{"LWS_CALLBACK_RAW_PROXY_CLI_CLOSE", 91},
	{"LWS_CALLBACK_RAW_PROXY_SRV_CLOSE", 92},
	{"LWS_CALLBACK_RAW_PROXY_CLI_WRITEABLE", 93},
	{"LWS_CALLBACK_RAW_PROXY_SRV_WRITEABLE", 94},
	{"LWS_CALLBACK_RAW_PROXY_CLI_ADOPT", 95},
	{"LWS_CALLBACK_RAW_PROXY_SRV_ADOPT", 96},
	{"LWS_CALLBACK_RAW_PROXY_CLI_BIND_PROTOCOL", 97},
	{"LWS_CALLBACK_RAW_PROXY_SRV_BIND_PROTOCOL", 98},
	{"LWS_CALLBACK_RAW_PROXY_CLI_DROP_PROTOCOL", 99},
	{"LWS_CALLBACK_RAW_PROXY_SRV_DROP_PROTOCOL", 100},
	{"LWS_CALLBACK_RAW_RX", 59},
	{"LWS_CALLBACK_RAW_CLOSE", 60},
	{"LWS_CALLBACK_RAW_WRITEABLE", 61},
	{"LWS_CALLBACK_RAW_ADOPT", 62},
	{"LWS_CALLBACK_RAW_CONNECTED", 101},
	{"LWS_CALLBACK_RAW_SKT_BIND_PROTOCOL", 81},
	{"LWS_CALLBACK_RAW_SKT_DROP_PROTOCOL", 82},
	{"LWS_CALLBACK_RAW_ADOPT_FILE", 63},
	{"LWS_CALLBACK_RAW_RX_FILE", 64},
	{"LWS_CALLBACK_RAW_WRITEABLE_FILE", 65},
	{"LWS_CALLBACK_RAW_CLOSE_FILE", 66},
	{"LWS_CALLBACK_RAW_FILE_BIND_PROTOCOL", 83},
	{"LWS_CALLBACK_RAW_FILE_DROP_PROTOCOL", 84},
	{"LWS_CALLBACK_TIMER", 73},
	{"LWS_CALLBACK_EVENT_WAIT_CANCELLED", 71},
	{"LWS_CALLBACK_CHILD_CLOSING", 69},
	{"LWS_CALLBACK_VHOST_CERT_AGING", 72},
	{"LWS_CALLBACK_VHOST_CERT_UPDATE", 74},
	{"LWS_CALLBACK_MQTT_NEW_CLIENT_INSTANTIATED", 200},
	{"LWS_CALLBACK_MQTT_IDLE", 201},
	{"LWS_CALLBACK_MQTT_CLIENT_ESTABLISHED", 202},
	{"LWS_CALLBACK_MQTT_SUBSCRIBED", 203},
	{"LWS_CALLBACK_MQTT_CLIENT_WRITEABLE", 204},
	{"LWS_CALLBACK_MQTT_CLIENT_RX", 205},
	{"LWS_CALLBACK_MQTT_UNSUBSCRIBED", 206},
	{"LWS_CALLBACK_MQTT_DROP_PROTOCOL", 207},
	{"LWS_CALLBACK_MQTT_CLIENT_CLOSED", 208},
	{"LWS_CALLBACK_MQTT_ACK", 209},
	{"LWS_CALLBACK_MQTT_RESEND", 210},
	{"LWS_CALLBACK_USER", 1000}
};

static void print_reason(char* title, int reason) {
	int i;
	int size = sizeof(callbackMap)/sizeof(LWS_CALLBACK_MAP_ENTRY);
	
	for (i = 0; i < size; i++) {
		if (callbackMap[i].reason == reason) {
			fprintf(stderr, "%s, %s(%d)\n", title, callbackMap[i].message, reason);
			break;
		}
	}
	if (i == size) {
		fprintf(stderr, "%s, Unknown(%d)\n", title, reason);
	}
}

#else
	#define print_reason(a,b)
	#define print_in(a,b,c)
#endif

enum protocols
{
	PROTOCOL_EXAMPLE = 0,
	PROTOCOL_COUNT
};

static int callback_example( struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len );

static struct lws_protocols protocols[] =
{
	{
		"example-protocol",
		callback_example,
		0,
		MAX_SERVER_RESPONSE_LEN,
	},
	{ NULL, NULL, 0, 0 } /* terminator */
};

static struct lws *web_socket = NULL;
struct lws_context *context = NULL;
static pthread_t g_writableThread = 0;

static void connect_to_server()
{
	struct lws_client_connect_info ccinfo = {0};
	
	if (context == NULL) return;
	
	ccinfo.context = context;
	ccinfo.address = "localhost";
	ccinfo.port = 8000;
	ccinfo.path = "/websocket";
	ccinfo.host = lws_canonical_hostname( context );
	ccinfo.origin = "origin";
	ccinfo.protocol = protocols[PROTOCOL_EXAMPLE].name;
	web_socket = lws_client_connect_via_info(&ccinfo);
}

static void* thread_writable(void *args)
{
	while (1) {
		lws_callback_on_writable( web_socket );
		sleep(5);
	}
	return NULL;
}

static int callback_example( struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len )
{
	print_reason("callback_example", reason);

	switch( reason )
	{
		case LWS_CALLBACK_CLIENT_ESTABLISHED:
			lws_callback_on_writable( wsi );
			break;

		case LWS_CALLBACK_CLIENT_RECEIVE: {
			char str[MAX_SERVER_RESPONSE_LEN+1] = {0};
			memcpy(str, in, len);	
			fprintf(stderr, "client got, in=[%s]\n", str);
			/* Handle incomming messages here. */
			break;
		}

		case LWS_CALLBACK_CLIENT_WRITEABLE:
		{
			unsigned char buf[LWS_SEND_BUFFER_PRE_PADDING + MAX_SERVER_RESPONSE_LEN + LWS_SEND_BUFFER_POST_PADDING];
			unsigned char *p = &buf[LWS_SEND_BUFFER_PRE_PADDING];
			size_t n = sprintf( (char *)p, "myclient");
			fprintf(stderr, "client write, [%s]\n", p);
			lws_write( wsi, p, n, LWS_WRITE_TEXT );
			break;
		}

		case LWS_CALLBACK_CLOSED:
		case LWS_CALLBACK_WSI_DESTROY:
			sleep(3);
			web_socket = NULL;
			connect_to_server();
			break;
		default:
			break;
	}

	return 0;
}

int main( int argc, char *argv[] )
{
	struct lws_context_creation_info info;
	memset( &info, 0, sizeof(info) );

#ifdef DEBUG
	lws_set_log_level(LLL_ERR | LLL_WARN | LLL_NOTICE | LLL_INFO | LLL_DEBUG | LLL_PARSER | LLL_HEADER | LLL_EXT | LLL_CLIENT | LLL_LATENCY | LLL_USER, NULL);
#endif

	info.port = CONTEXT_PORT_NO_LISTEN;
	info.protocols = protocols;
	info.gid = -1;
	info.uid = -1;

	context = lws_create_context( &info );

	if( !web_socket ) {
		connect_to_server();
	}
	
	pthread_create(&g_writableThread, NULL, thread_writable, NULL);
	lws_callback_on_writable( web_socket );
	while( 1 ) {
		lws_service( context, 0 );
	}

	lws_context_destroy( context );
	context = NULL;

	return 0;
}