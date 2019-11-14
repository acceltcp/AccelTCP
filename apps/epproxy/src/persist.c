#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include "http_stream.h"
#include "http_parser.h"
#include "util.h"
#include "hash.h"
#include "epproxy.h"
#include "persist.h"
/*----------------------------------------------------------------------------*/
int
HandleRequestPersistence(struct sticky_table *sticky_map, 
						 struct http_stream *hs)
{
	char cookie_prefix[COOKIE_PREFIX_LEN + 1];     // 1 for null
	char *cookie_start, *cookie_value, *cookie_end = NULL;
	char *end;
	char temp_char = 0;
	int i;
	struct backend_pool* bpool = &g_prx_ctx->bpool[hs->nif_out];
	int bpool_size = get_backend_poolsize(bpool);
	struct backend_info* binfo;

	if (g_prx_ctx->persist_method == PM_NONE)
		return RES_RUN_LB;

	/* if the end of the header field is not detected,
	   need to retrieve the remaining bytes for the header */
	end = NULL;
	if ((end = strstr(hs->rbuf->data, CRLFCRLF))) {
		end += (sizeof(CRLFCRLF) - 1);
	}
	else if ((end = strstr(hs->rbuf->data, LFLF))) {
		end += (sizeof(LFLF) - 1);
	}
	else
		assert(0); /* should not happen here */
	

	/* search for a Cookie field in the request */
	sprintf(cookie_prefix, "Cookie: %s=", g_prx_ctx->persist_cookie);
	cookie_start = strstr(hs->rbuf->data, cookie_prefix);
	if (cookie_start != NULL) {
		cookie_value = cookie_start + strlen(cookie_prefix);
		for (cookie_end = cookie_value; (*cookie_end) != '~'
				 && (*cookie_end) != '\r' && (*cookie_end) != '\n';
			 cookie_end++) {
			if ((*cookie_end) == 0) {
				TRACE_ERROR("wrong cookie value (should not happen)\n");
				exit(-1);
			}
				
		}
	}		
		
	/* process cookie field that can be used for persistence */
	if (g_prx_ctx->persist_method == PM_SET_COOKIE) {
		/* if there is a cookie placed for session persistence,
		   remove the cookie & forward it to the corresponding server */
		if (cookie_start != NULL && *(cookie_start - 1) == '\n' &&
			((*cookie_end) == '\r' || (*cookie_end) == '\n')) {				
			temp_char = (*cookie_end);
			(*cookie_end) = 0;
			
			/* compare cookie value for each server in the backend pool */
			for (i = 0; i < bpool_size; i++) {
				binfo = get_server_from_bpool_by_pos(bpool, i);	
				if (!strcmp(cookie_value, binfo->name)) {
					/* found a server that meets session persistence */
					hs->backend = binfo;
					/* get back the original character */
					(*cookie_end) = temp_char;
					/* remove the entire line and the preceding \r\n (or \n) */
					cookie_start -= (*(cookie_start - 2) == '\r')? 2 : 1;
					memmove(cookie_start, cookie_end,
							hs->rbuf->data_len - (end - cookie_end));
					hs->rbuf->data_len -= (cookie_end - cookie_start);
					return RES_FOUND_PERSIST;
				}					
			}
			(*cookie_end) = temp_char;
		}
	}
	else if (g_prx_ctx->persist_method == PM_APPEND_COOKIE) {
		/* if there is a cookie prefix placed for session persistence,
		   remove the prefix & forward it to the corresponding server */
		if (cookie_start != NULL && (*cookie_end) == '~') {				
			temp_char = (*cookie_end);
			(*cookie_end) = 0;

			/* compare cookie value for each server in the backend pool */
			for (i = 0; i < bpool_size; i++) {
				binfo = get_server_from_bpool_by_pos(bpool, i);	
				if (!strcmp(cookie_value, binfo->name)) {
					/* found a server that meets session persistence */
					hs->backend = binfo;
					/* get back the original character */
					(*cookie_end) = temp_char;
					/* we should remove including '~' */
					cookie_end += 1;
					memmove(cookie_value, cookie_end,
							hs->rbuf->data_len - (end - cookie_end));
					hs->rbuf->data_len -= (cookie_end - cookie_value);
					return RES_FOUND_PERSIST;
				}
			}
			(*cookie_end) = temp_char;								
				
		}			
		/* if not, just follow the LB result by its algorithm */
		return RES_RUN_LB;
	}
	else if (g_prx_ctx->persist_method == PM_LEARN_COOKIE) {
		/* if its cookie is learned one (e.g., exists in its sticky table),
		   forward it to the corresponding server */
		if (cookie_start != NULL && *(cookie_start - 1) == '\n' &&
			((*cookie_end) == '\r' || (*cookie_end) == '\n')) {
			temp_char = (*cookie_end);
			(*cookie_end) = 0;

			/* search for a cookie_value in sticky table */
			struct sticky_ent* walk;
			TAILQ_FOREACH(walk, sticky_map, link) {
				if (!strcmp(walk->value, cookie_value)) {
					hs->backend = walk->backend;
					(*cookie_end) = temp_char;
					return RES_FOUND_PERSIST;
				}
			}
			(*cookie_end) = temp_char;
		}
	}

	/* if not, just follow the LB result by its algorithm */
	return RES_RUN_LB;	
}
/*----------------------------------------------------------------------------*/
int
HandleResponsePersistence(struct sticky_table *sticky_map, 
						  struct http_stream *hs,
						  struct http_stream *peer_hs,
						  char *sticky_value)
{
	char cookie_prefix[COOKIE_PREFIX_LEN + 1];     // 1 for null
	char cookie_insert[COOKIE_TOTAL_LEN + 1];      // 1 for null
	char server_prefix[MAX_SERVER_NAME_LEN + 2];   // 1 for '~' + 1 for null
	char *cookie_start, *cookie_value, *cookie_end = NULL;
	char *end, *insert = NULL;
	char temp_char = 0;
	int ret;	

	if (g_prx_ctx->persist_method == PM_NONE)
		return RES_RUN_LB;

	/* if the end of the header field is not detected,
	   need to retrieve the remaining bytes for the header */
	end = NULL;
	if ((end = strstr(hs->rbuf->data, CRLFCRLF))) {
		insert = end; /* place to put header */
		end += (sizeof(CRLFCRLF) - 1);
	}
	else if ((end = strstr(hs->rbuf->data, LFLF))) {
		insert = end;
		end += (sizeof(LFLF) - 1);
	}
	else
		assert(0); /* should not happen here */

	/* search for a Set-Cookie field in the request */
	sprintf(cookie_prefix, "Set-Cookie: %s=", g_prx_ctx->persist_cookie);
	cookie_start = strstr(hs->rbuf->data, cookie_prefix);
	if (cookie_start != NULL) {
		cookie_value = cookie_start + strlen(cookie_prefix);
		for (cookie_end = cookie_value; (*cookie_end) != '~'
				 && (*cookie_end) != '\r' && (*cookie_end) != '\n';
			 cookie_end++) {
			if ((*cookie_end) == 0) {
				TRACE_ERROR("wrong cookie value (should not happen)\n");
				exit(-1);
			}				
		}
	}		

	/* process cookie field that can be used for persistence */
	if (g_prx_ctx->persist_method == PM_SET_COOKIE) {
		assert(insert != NULL);
			
		/* if no cookie in response, place one to mark its backend */
		if (cookie_start == NULL) {
			ret = sprintf(cookie_insert, "\r\nSet-Cookie: %s=%s",
						  g_prx_ctx->persist_cookie,
						  peer_hs->backend->name);
			memmove(insert + ret, insert,
					hs->rbuf->data_len - (insert - hs->rbuf->data));
			memcpy(insert, cookie_insert, ret);
			hs->rbuf->data_len += ret;
			if (peer_hs->keep_alive)
				peer_hs->bytes_to_write += ret;
			return RES_FOUND_PERSIST;
		}
		/* if there already exists, skip it */
		else {
			return RES_FOUND_PERSIST;
		}
	}
	else if (g_prx_ctx->persist_method == PM_APPEND_COOKIE) {
		/* if there is no matching cookie, skip it */
		if (cookie_start == NULL) {
			return RES_FOUND_PERSIST;
		}
		/* if there is a matching cookie, append a prefix */
		else {
			assert(cookie_value != NULL && end != NULL);
			/* server prefix is allocated to have MAX_SERVER_NAME_LEN + 2 */
			ret = sprintf(server_prefix, "%s~",
						  peer_hs->backend->name);
			memmove(cookie_value + ret, cookie_value,
					hs->rbuf->data_len - (cookie_value - hs->rbuf->data));
			memcpy(cookie_value, server_prefix, ret);
				
			hs->rbuf->data_len += ret;
			if (peer_hs->keep_alive)
				peer_hs->bytes_to_write += ret;
			return RES_FOUND_PERSIST;
		}
			
	}
	else if (g_prx_ctx->persist_method == PM_LEARN_COOKIE) {
		/* if there is a matching cookie, insert it to the sticky table */
		if (cookie_start != NULL && *(cookie_start - 1) == '\n' &&
			((*cookie_end) == '\r' || (*cookie_end) == '\n')) {
			temp_char = (*cookie_end);
			(*cookie_end) = 0;

			/* try adding to the table */
			struct sticky_ent* walk;
			TAILQ_FOREACH(walk, sticky_map, link) {
				if (!strcmp(walk->value, cookie_value)) {
					return RES_FOUND_PERSIST;
				}
			}

			strcpy(sticky_value, cookie_value);
			(*cookie_end) = temp_char;
			return RES_ADD_STICKY_TABLE;
		}
		return RES_FOUND_PERSIST;
	}
	else
		assert(0);
	
	return RES_RUN_LB;
}
/*----------------------------------------------------------------------------*/
