/*----------------------------------------------------------------------------*/
#define _GNU_SOURCE
#include <string.h>
#include <sys/types.h>
#include <assert.h>
#include <arpa/inet.h>
#include <ctype.h>
#include "util.h"
#include "http_parser.h"
#include "config.h"
/*----------------------------------------------------------------------------*/
//#define VALIDATE_RESPONSE       /* whether to validate response from server */
/*----------------------------------------------------------------------------*/
#define HTTP_HDR       "http://"
#define HTTP_HOST      "\nHost: "
#define HTTP_CONN      "\nConnection: "
#define HTTP_LEN       "\nContent-Length: "
#define HTTP_KEEPALIVE "keep-alive"
#define HTTP_CLOSE     "close"
/*----------------------------------------------------------------------------*/
#define HTTP_HDR_400 "HTTP/1.0 400 Bad Request\r\n"                \
                     "Content-Type: text/html\r\n%s"
#define HTTP_HDR_405 "HTTP/1.0 405 Method Not Allowed\r\n"         \
	                 "Content-Type: text/html\r\n%s"
#define HTTP_HDR_500 "HTTP/1.0 500 Internal Server Error\r\n"      \
                     "Content-Type: text/html\r\n%s"
#define HTTP_HDR_505 "HTTP/1.0 505 HTTP Version Not Supported\r\n" \
	                 "Content-Type: text/html\r\n%s"
/*----------------------------------------------------------------------------*/
#define HTTP_BDY_400 "Request format is wrong!"
#define HTTP_BDY_405 "Requested method is not implemented!"
#define HTTP_BDY_500 "Cannot connect to the server!"
#define HTTP_BDY_505 "HTTP version 2.0 is not supported!"
/*----------------------------------------------------------------------------*/
enum {REQUEST_LINE, HOST_LINE};
/*----------------------------------------------------------------------------*/
#define SUCCESS 1
#define FAILURE 0
/*----------------------------------------------------------------------------*/
#define SKIP_SPACE(x) while((*x) && isspace(*x)) x++;
#define SKIP_CHAR(x) while((*x) && !isspace(*x)) x++;
/*---------------------------------------------------------------------------*/
uint32_t
sdbm (char* str, unsigned int len)
{
    uint32_t hash = 0;
	uint32_t i;

	for (i = 0; i < len; i++)
        hash = (*str) + (hash << 6) + (hash << 16) - hash;

    return hash;
}
/*----------------------------------------------------------------------------*/
int 
ParseHTTPRequest(struct http_stream *hs, char **host_pos)
{
	int client_http_ver;
	char *buf, *end, *header_field, *temp;
	char temp_char;
	char* rb = hs->rbuf->data;

	/* if the end of the header field is not detected,
	   need to retrieve the remaining bytes for the header */
	end = NULL;
	if ((end = strstr(rb, CRLFCRLF)))
		end += (sizeof(CRLFCRLF) - 1);
	else if ((end = strstr(rb, LFLF))) /* popular webservers accept LFLF */
		end += (sizeof(LFLF) - 1);
	else {
		/* we want more data to parse header*/
		return RR_MORE;
	}

	/* start parsing the HTTP reqeust */
	buf = rb;
	
	/* [request-line] = [method SP request-target SP HTTP-version CRLF] */
	/* method */
	if (!strncmp(buf, "GET ", sizeof("GET ") - 1))
		buf += (sizeof("GET ") - 1);
	else if (!strncmp(buf, "HEAD ", sizeof("HEAD ") - 1))
		buf += (sizeof("HEAD ") - 1);
	/* for now, only HTTP GET and HEAD methods are supported */	
	else if (!strncmp(buf, "PUT ",      sizeof("PUT ") - 1)     ||
			 !strncmp(buf, "POST ",     sizeof("POST ") - 1)    ||
			 !strncmp(buf, "TRACE ",    sizeof("TRACE ") - 1)   ||
			 !strncmp(buf, "DELETE ",   sizeof("DELETE ") - 1)  ||
			 !strncmp(buf, "CONNECT ",  sizeof("CONNECT ") - 1) ||
			 !strncmp(buf, "OPTIONS ",  sizeof("OPTIONS ") - 1) ) {
		return RR_RETURN_501; /* Not Implemented*/
	}
	
	/* request-target should come right after [method SP] */
	if (isspace(*buf))
		return RR_RETURN_400; /* Bad Request */

	/* extract URI if required */
	temp = buf;
	SKIP_CHAR(temp);
	temp_char = (*temp);
	(*temp) = 0;
	hs->uri = strdup(buf);
	(*temp) = temp_char;
	
	/* move on to the HTTP-version */
	SKIP_CHAR(buf);
	if (*buf != ' ')
		return RR_RETURN_400; /* Bad Request */
	buf++;

	/* HTTP-version should come right after [request-target SP] */
	if (isspace(*buf))
		return RR_RETURN_400; /* Bad Request */
	
	/* check if valid and supportable HTTP-version comes */
	if (strncmp(buf, "HTTP/", sizeof("HTTP/") - 1))
		return RR_RETURN_400; /* Bad Request */		
	buf += (sizeof("HTTP/") - 1);

	if (!isdigit(*buf))
		return RR_RETURN_400; /* Bad Request */
	else if (*buf != '1')
		return RR_RETURN_505; /* HTTP Version Not Supported */
	buf++;

	if (*buf != '.')
		return RR_RETURN_400; /* Bad Request */
	buf++;

	if (*buf == '0') {
		client_http_ver = HTTP_VER_1_0;
		hs->keep_alive = 0;  /* HTTP/1.0 -> non-persistent by default */
	}
	else if (*buf == '1') {
		client_http_ver = HTTP_VER_1_1;
		hs->keep_alive = 1;  /* HTTP/1.1 -> persistent by default */
	}
	else if (!isdigit(*buf))
		return RR_RETURN_400; /* Bad Request */
	else
		return RR_RETURN_505; /* HTTP Version Not Supported */
	buf++;
	
	/* we expect CRLF (or LF) at the end of request-line */
	if (!(*buf == '\r' && *(buf + 1) == '\n') &&
		!(*(buf + 1) == '\n'))
		return RR_RETURN_400; /* Bad Request */

	/* since we finished parsing request-line,
	   now parse header fields that are required */
	header_field = buf;

	/* Host: */
	if ((buf = strcasestr(header_field, HTTP_HOST)) != NULL) {		
		buf += (sizeof(HTTP_HOST) - 1);
		(*host_pos) = buf;
	}
	/* HTTP 1.1 request without Host field -> invalid */
	else if (client_http_ver == HTTP_VER_1_1)
		return RR_RETURN_400;

	/* Connection: */
	if ((buf = strstr(header_field, HTTP_CONN)) != NULL) {
		buf += (sizeof(HTTP_CONN) - 1); 
		temp = buf;
		
		SKIP_CHAR(temp);
		temp_char = (*temp);
		(*temp) = 0;	   

		/* override the default value (Closed for 1.0, Keep-alive for 1.1) */
		if (!strcasecmp(buf, HTTP_KEEPALIVE))
			hs->keep_alive = 1;
		else if (!strcasecmp(buf, HTTP_CLOSE))
			hs->keep_alive = 0;
		else
			return RR_RETURN_400;

		(*temp) = temp_char;
	}
	
	return RR_DONE;	
}
/*----------------------------------------------------------------------------*/
int 
ParseHTTPResponse(struct http_stream *hs, struct http_stream *peer_hs)
{
	char *end, *buf, *temp;
	char *rb = hs->rbuf->data;
	char temp_char;
	char *header_field;

	/* if the end of the header field is not detected,
	   need to retrieve the remaining bytes for the header */
	end = NULL;
	if ((end = strstr(rb, CRLFCRLF)))
		end += (sizeof(CRLFCRLF) - 1);
	else if ((end = strstr(rb, LFLF)))
		end += (sizeof(LFLF) - 1);
	else {
		/* we want more data to parse header*/
		return RR_MORE;
	}   

#ifdef VALIDATE_RESPONSE	
	/* start parsing the response */
	buf = rb;

	/* status-line = HTTP-version SP status-code SP reason-phrase CRLF */

	/* HTTP-version */
	/* check if valid and supportable HTTP-version comes */
	if (strncmp(buf, "HTTP/", sizeof("HTTP/") - 1))
		return RR_ERROR_RESPONSE;
	buf += (sizeof("HTTP/") - 1);

	/* epproxy only cares HTTP version format, but not the value itself */
	if (!isdigit(*buf))
		return RR_ERROR_RESPONSE;
	buf++;

	if ((*buf) != '.')
		return RR_ERROR_RESPONSE;
	buf++;

	if (!isdigit(*buf))
		return RR_ERROR_RESPONSE;
	buf++;

	/* check if it has SP in between HTTP-version and status-code */
	if ((*buf) != ' ')
		return RR_ERROR_RESPONSE;
	buf++;

	/* status-code: check if it is 3-digit code */
	/* XXX: if server responses with 5xx code, we can exclude it from backend pool */
	if (!isdigit(*buf) || !isdigit(*(buf + 1)) || !isdigit(*(buf + 2)))
		return RR_ERROR_RESPONSE;
	buf += 3;
	
	/* check if it has SP in between status-code and reason-phrase */
	if ((*buf) != ' ')
		return RR_ERROR_RESPONSE;
	buf++;

	/* we don't validate further, so we're done!
	 * (RFC 7230 says that "A client should ignore reason-phrase") */
	if ((buf = strstr(buf, "\n")))
 		buf++;
	header_field = buf;

#else   /*  !VALIDATE_RESPONSE  */

	if ((header_field = strstr(rb, "\n")))
		header_field++;

#endif  /*  !VALIDATE_RESPONSE  */
	
	/* Parse content-length field */
	if ((buf = strstr(header_field, HTTP_LEN)) != NULL) {
		buf += (sizeof(HTTP_LEN) - 1); 
		temp = buf;

		SKIP_CHAR(temp);
		temp_char = (*temp);
		(*temp) = 0;

		if (peer_hs->keep_alive)
			peer_hs->bytes_to_write = (int) (end - rb) + atoi(buf);
		
		(*temp) = temp_char;
	}
	else {
		/* XXX: Handle the case where HTTP response does not contain it */
		return RR_ERROR_RESPONSE;
	}
	
	return RR_DONE;
}
/*----------------------------------------------------------------------------*/
