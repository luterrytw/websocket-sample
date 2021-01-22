#include <libwebsockets.h>
#include <string.h>
#include <stdio.h>

#include "server.h"


////////////////////////////////////////////////////////////////////////
// debug function
////////////////////////////////////////////////////////////////////////

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

static void print_in(char* title, char* in, size_t len)
{
	if (len <= 0) {
		fprintf(stderr, "ttt 3\n");
		return;
	}

	char* str = malloc(len+1);
	strcpy(str, in);
	str[len] = '\0';
	fprintf(stderr, "%s, in=[%s]\n", title, (char*) str);
	free(str);
}

#else
	#define print_reason(a,b)
	#define print_in(a,b,c)
#endif


////////////////////////////////////////////////////////////////////////
// libwebsocket callback
////////////////////////////////////////////////////////////////////////
static int callback_http( struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len )
{
	uint8_t buf[LWS_PRE + MAX_SERVER_RESPONSE_LEN]; // 1024 bytes for http header and data
	uint8_t *start = &buf[LWS_PRE];
	uint8_t *p = start, *end = &buf[sizeof(buf) - LWS_PRE - 1];
			
	print_reason("callback_http", reason);
	print_in("LWS_CALLBACK_HTTP", in, len);
	switch( reason )
	{
		case LWS_CALLBACK_HTTP:
			if (!strcmp((const char *)in, URI_KV_POST)) {
				fprintf(stderr, "ttt 1\n");
				return 0; // return 0 to allow http post
			}
			fprintf(stderr, "ttt 2\n");
			break;

		case LWS_CALLBACK_HTTP_BODY_COMPLETION:
		{
			char* data = "{'seq':123}";		
			if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK, "application/json", LWS_ILLEGAL_HTTP_CONTENT_LEN, &p, end))
				return 1;
			if (lws_finalize_write_http_header(wsi, start, &p, end))
				return 1;

			p = start;
			p += lws_snprintf((char *)start, lws_ptr_diff_size_t(end, p), "%s", data);
			lws_write(wsi, (uint8_t *) start, lws_ptr_diff_size_t(p, start), LWS_WRITE_HTTP);
			if (lws_http_transaction_completed(wsi)) {
				return -1;
			}
			return 0;
		}
		default:
			break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);;
}

struct payload
{
	unsigned char data[LWS_SEND_BUFFER_PRE_PADDING + MAX_SERVER_RESPONSE_LEN + LWS_SEND_BUFFER_POST_PADDING];
	size_t len;
} received_payload;

static int callback_example( struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len )
{
	print_reason("LWS_CALLBACK_example", reason);
	switch( reason )
	{
		case LWS_CALLBACK_RECEIVE: {
			char str[MAX_SERVER_RESPONSE_LEN+1] = {0};
			memcpy(str, in, len);	
			fprintf(stderr, "server got, in=[%s]\n", str);

			lws_callback_on_writable_all_protocol( lws_get_context( wsi ), lws_get_protocol( wsi ) );
			break;
		}

		case LWS_CALLBACK_SERVER_WRITEABLE: {
			char *response = (char*) &received_payload.data[LWS_SEND_BUFFER_PRE_PADDING];
			strcpy(response, "myserver");
			received_payload.len = strlen(response);
			fprintf(stderr, "server write, [%s]\n", (char*) &received_payload.data[LWS_SEND_BUFFER_PRE_PADDING]);
			lws_write( wsi, &received_payload.data[LWS_SEND_BUFFER_PRE_PADDING], received_payload.len, LWS_WRITE_TEXT );
			break;
		}

		default:
			break;
	}

	return 0;
}

enum protocols
{
	PROTOCOL_HTTP = 0,
	PROTOCOL_EXAMPLE,
	PROTOCOL_COUNT
};

static struct lws_protocols protocols[] =
{
	/* The first protocol must always be the HTTP handler */
	{
		"http-only",   /* name */
		callback_http, /* callback */
		0,             /* No per session data. */
		0,             /* max frame size / rx buffer */
	},
	{
		"example-protocol",
		callback_example,
		0,
		MAX_SERVER_RESPONSE_LEN,
	},
	{ NULL, NULL, 0, 0 } /* terminator */
};

int main( int argc, char *argv[] )
{
	struct lws_context_creation_info info;
	struct lws_context *context;
	
	memset( &info, 0, sizeof(info) );
	
#ifdef DEBUG
	lws_set_log_level(LLL_ERR | LLL_WARN | LLL_NOTICE | LLL_INFO | LLL_DEBUG | LLL_PARSER | LLL_HEADER | LLL_EXT | LLL_CLIENT | LLL_LATENCY | LLL_USER, NULL);
#endif

	info.port = KV_SERVER_PORT;
	info.protocols = protocols;
	//info.mounts = &httpMount;
	info.gid = -1;
	info.uid = -1;

	context = lws_create_context( &info );

	while( 1 )
	{
		lws_service( context, /* timeout_ms = */ 1000000 );
	}

	lws_context_destroy( context );

	return 0;
}