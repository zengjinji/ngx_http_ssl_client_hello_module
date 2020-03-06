
/*
 * Copyright (C) 2020-2020 ZengJinji
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_ssl_client_hello.h>


typedef struct {
    ngx_flag_t           enable;
} ngx_http_ssl_client_hello_srv_conf_t;


static ngx_int_t ngx_http_ssl_client_server_name(ngx_ssl_conn_t *ssl_conn,
    ngx_connection_t  *c, ngx_str_t **hostp);

static void *ngx_http_ssl_client_hello_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_ssl_client_hello_merge_srv_conf(ngx_conf_t *cf,
    void *parent, void *child);


static ngx_command_t  ngx_http_ssl_client_hello_commands[] = {

    { ngx_string("ssl_client_hello"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_client_hello_srv_conf_t, enable),
      NULL },

    ngx_null_command
};


static ngx_http_module_t  ngx_http_ssl_client_hello_module_ctx = {
    NULL,                                         /* preconfiguration */
    NULL,                                         /* postconfiguration */
                                                 
    NULL,                                         /* create main configuration */
    NULL,                                         /* init main configuration */
                                              
    ngx_http_ssl_client_hello_create_srv_conf,    /* create server configuration */
    ngx_http_ssl_client_hello_merge_srv_conf,     /* merge server configuration */

    NULL,                                         /* create location configuration */
    NULL                                          /* merge location configuration */
};


ngx_module_t  ngx_http_ssl_client_hello_module = {
    NGX_MODULE_V1,
    &ngx_http_ssl_client_hello_module_ctx,    /* module context */
    ngx_http_ssl_client_hello_commands,       /* module directives */
    NGX_HTTP_MODULE,                          /* module type */
    NULL,                                     /* init master */
    NULL,                                     /* init module */
    NULL,                                     /* init process */
    NULL,                                     /* init thread */
    NULL,                                     /* exit thread */
    NULL,                                     /* exit process */
    NULL,                                     /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_http_ssl_client_hello_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_ssl_client_hello_srv_conf_t    *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ssl_client_hello_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_ssl_client_hello_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{

    ngx_http_ssl_srv_conf_t                 *sscf;
    ngx_http_ssl_client_hello_srv_conf_t    *prev = parent;
    ngx_http_ssl_client_hello_srv_conf_t    *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);

    if (conf->enable) {
        sscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_ssl_module);
        if (sscf && sscf->ssl.ctx) {
            SSL_CTX_set_client_hello_cb(sscf->ssl.ctx,
                                        ngx_http_ssl_client_hello_handler, NULL);
        }
    }

    return NGX_CONF_OK;
}


// in openssl, sni parse behind client_hello_cb
static ngx_int_t
ngx_http_ssl_client_server_name(ngx_ssl_conn_t *ssl_conn,
    ngx_connection_t  *c, ngx_str_t **hostp)
{
    size_t                  remaining, len;
    ngx_str_t              *host;
    const unsigned char    *p;

    remaining = 0;

    if (!SSL_client_hello_get0_ext(ssl_conn, TLSEXT_TYPE_server_name, &p,
                                   &remaining)
        || remaining <= 2) {
        return NGX_ERROR;
    }

    len = (*(p++) << 8);
    len += *(p++);
    if (len + 2 != remaining) {
        return NGX_ERROR;
    }
    remaining = len;

    if (remaining == 0 || *p++ != TLSEXT_NAMETYPE_host_name) {
        return NGX_ERROR;
    }
    remaining--;

    if (remaining <= 2) {
        return NGX_ERROR;
    }
    len = (*(p++) << 8);
    len += *(p++);
    if (len + 2 > remaining) {
        return NGX_ERROR;
    }
    remaining = len;

    host = ngx_pcalloc(c->pool, sizeof(ngx_str_t));
    if (host == NULL) {
        return NGX_ERROR;
    }

    host->data = (u_char *) p;
    host->len = len;

    *hostp = host;

    return NGX_OK;
}


int
ngx_http_ssl_client_hello_handler(ngx_ssl_conn_t *ssl_conn,
    int *al, void *arg)
{
    ngx_str_t                   *host;
    ngx_connection_t            *c;
    ngx_http_connection_t       *hc;
    ngx_http_ssl_srv_conf_t     *sscf, *default_sscf;
    ngx_http_core_srv_conf_t    *cscf;

    c = ngx_ssl_get_connection(ssl_conn);
    hc = c->data;

    if (ngx_http_ssl_client_server_name(ssl_conn, c, &host) != NGX_OK) {
        return NGX_HTTP_SSL_CLIENT_HELLO_SUCCESS;
    }

    if (ngx_http_validate_host(host, c->pool, 1) != NGX_OK) {
        return NGX_HTTP_SSL_CLIENT_HELLO_SUCCESS;
    }

    if (ngx_http_find_virtual_server(c, hc->addr_conf->virtual_names, host,
                                     NULL, &cscf)
        != NGX_OK)
    {
        return NGX_HTTP_SSL_CLIENT_HELLO_SUCCESS;
    }

    sscf = ngx_http_get_module_srv_conf(cscf->ctx, ngx_http_ssl_module);
    cscf = hc->addr_conf->default_server;
    default_sscf = ngx_http_get_module_srv_conf(cscf->ctx, ngx_http_ssl_module);

    if ((sscf->ciphers.len != default_sscf->ciphers.len)
        || (ngx_memcmp(sscf->ciphers.data, default_sscf->ciphers.data, sscf->ciphers.len) != 0))
    {
        SSL_set_cipher_list(ssl_conn, (char *) sscf->ciphers.data);
    }

    if (sscf->protocols != default_sscf->protocols) {
        SSL_clear_options(ssl_conn,
                          SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3|SSL_OP_NO_TLSv1);
        if (!(sscf->protocols & NGX_SSL_SSLv2)) {
            SSL_set_options(ssl_conn, SSL_OP_NO_SSLv2);
        }
        if (!(sscf->protocols & NGX_SSL_SSLv3)) {
            SSL_set_options(ssl_conn, SSL_OP_NO_SSLv3);
        }
        if (!(sscf->protocols & NGX_SSL_TLSv1)) {
            SSL_set_options(ssl_conn, SSL_OP_NO_TLSv1);
        }
#ifdef SSL_OP_NO_TLSv1_1
        SSL_clear_options(ssl_conn, SSL_OP_NO_TLSv1_1);
        if (!(sscf->protocols & NGX_SSL_TLSv1_1)) {
            SSL_set_options(ssl_conn, SSL_OP_NO_TLSv1_1);
        }
#endif
#ifdef SSL_OP_NO_TLSv1_2
        SSL_clear_options(ssl_conn, SSL_OP_NO_TLSv1_2);
        if (!(sscf->protocols & NGX_SSL_TLSv1_2)) {
            SSL_set_options(ssl_conn, SSL_OP_NO_TLSv1_2);
        }
#endif
#ifdef SSL_OP_NO_TLSv1_3
        SSL_clear_options(ssl_conn, SSL_OP_NO_TLSv1_3);
        if (!(sscf->protocols & NGX_SSL_TLSv1_3)) {
            SSL_set_options(ssl_conn, SSL_OP_NO_TLSv1_3);
        }
#endif
    }

    return NGX_HTTP_SSL_CLIENT_HELLO_SUCCESS;
}
