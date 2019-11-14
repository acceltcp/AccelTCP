#ifndef __HTTP_PARSER_H_
#define __HTTP_PARSER_H_
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include "http_stream.h"
/*----------------------------------------------------------------------------*/
#define HTTP_DEFAULT_VER  "1.1"          /* epproxy uses HTTP/1.1 by default */
enum {HTTP_VER_1_0, HTTP_VER_1_1};    /* and we don't support HTTP/2 for now */
/*----------------------------------------------------------------------------*/
/* HTTP message parsing result */
enum {RR_MORE,
	  RR_DONE,
	  RR_ERROR_RESPONSE, /* wrong format or invalid value in server response */
	  RR_RETURN_400,
	  RR_RETURN_501,
	  RR_RETURN_505};
/*----------------------------------------------------------------------------*/
#define CRLFCRLF "\r\n\r\n"
#define LFLF     "\n\n"
#define CRLF     "\r\n"
#define LF       "\n"
/*----------------------------------------------------------------------------*/
int 
ParseHTTPRequest(struct http_stream *hs, char **host_pos);
/*----------------------------------------------------------------------------*/
int 
ParseHTTPResponse(struct http_stream *hs, struct http_stream *peer_hs);
/*----------------------------------------------------------------------------*/
#endif
