/*
 * Copyright (C) 2002 Stichting NLnet, Netherlands, stichting@nlnet.nl.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all
 * copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND STICHTING NLNET
 * DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
 * STICHTING NLNET BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
 * OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE
 * USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * The development of Dynamically Loadable Zones (DLZ) for Bind 9 was
 * conceived and contributed by Rob Butler.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all
 * copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ROB BUTLER
 * DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
 * ROB BUTLER BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
 * OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE
 * USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef SDLZHELPER_H
#define SDLZHELPER_H

/*
 * Types
 */
#define SDLZH_REQUIRE_CLIENT	0x01
#define SDLZH_REQUIRE_QUERY	0x02
#define SDLZH_REQUIRE_RECORD	0x04
#define SDLZH_REQUIRE_ZONE	0x08

typedef struct query_segment query_segment_t;
typedef ISC_LIST(query_segment_t) query_list_t;
typedef struct dbinstance dbinstance_t;
typedef ISC_LIST(dbinstance_t) db_list_t;

/*
* a query segment is all the text between our special tokens
* special tokens are %zone%, %record%, %client%
*/
struct query_segment {
  void				*sql;
  unsigned int			strlen;
  isc_boolean_t			direct;
  ISC_LINK(query_segment_t)	link;
};

struct dbinstance {
  void			  *dbconn;
  query_list_t		  *allnodes_q;
  query_list_t		  *allowxfr_q;
  query_list_t		  *authority_q;
  query_list_t		  *findzone_q;
  query_list_t		  *lookup_q;
  query_list_t		  *countzone_q;
  char			  *query_buf;
  char			  *zone;
  char			  *record;
  char			  *client;

  /* Helper functions from the dlz_dlopen driver */
  log_t                   *log;
  dns_sdlz_putrr_t        *putrr;
  dns_sdlz_putnamedrr_t   *putnamedrr;
  dns_dlz_writeablezone_t *writeable_zone;
};

/*
 * Method declarations
 */

/* see the code in sdlz_helper.c for more information on these methods */

static void
sdlz_destroy_querylist(query_list_t **querylist);

static isc_result_t
sdlzh_build_querylist(dbinstance_t *dbi, const char *query_str, char **zone,
                      char **record, char **client, query_list_t **querylist,
                      unsigned int flags);

char *
sdlzh_build_querystring(query_list_t *querylist);

isc_result_t
sdlzh_build_sqldbinstance(const char *allnodes_str,
                          const char *allowxfr_str, const char *authority_str,
                          const char *findzone_str, const char *lookup_str,
                          const char *countzone_str, dbinstance_t **dbi);

void
sdlzh_destroy_sqldbinstance(dbinstance_t *dbi);

char *
sdlzh_get_parameter_value(const char *input, const char* key);

#endif /* SDLZHELPER_H */
