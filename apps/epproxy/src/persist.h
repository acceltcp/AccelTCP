#ifndef HTTP_PERSIST_H 
#define HTTP_PERSIST_H 
#include <sys/queue.h>
#include "http_stream.h"
#include "backend_pool.h"
#include "config.h"
/*----------------------------------------------------------------------------*/
enum {RES_RUN_LB,
	  RES_FOUND_PERSIST,
	  RES_ADD_STICKY_TABLE};
/*----------------------------------------------------------------------------*/
enum {PM_NONE,
	  PM_SET_COOKIE,
	  PM_APPEND_COOKIE,
	  PM_LEARN_COOKIE};
/*----------------------------------------------------------------------------*/
#define COOKIE_VALUE_LEN       100
/*----------------------------------------------------------------------------*/
typedef struct sticky_ent {
	char  value[COOKIE_VALUE_LEN + 1];
	struct backend_info* backend;

	TAILQ_ENTRY (sticky_ent) link;

} sticky_ent;
/*----------------------------------------------------------------------------*/
TAILQ_HEAD (sticky_table, sticky_ent);  /* sticky table */
/*----------------------------------------------------------------------------*/
int
HandleRequestPersistence(struct sticky_table *sticky_map, 
						 struct http_stream *hs);
/*----------------------------------------------------------------------------*/
int
HandleResponsePersistence(struct sticky_table *sticky_map, 
						  struct http_stream *hs,
						  struct http_stream *peer_hs,
						  char *sticky_value);
/*----------------------------------------------------------------------------*/
#endif
