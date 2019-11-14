#ifndef HTTP_BACKEND_H 
#define HTTP_BACKEND_H 
#include "http_stream.h"
#include "persist.h"
#include "config.h"
/*----------------------------------------------------------------------------*/
void
DecideBackendServer(struct sticky_table *sticky_map,
					int* rr_count, struct http_stream *hs);
/*----------------------------------------------------------------------------*/
#endif
