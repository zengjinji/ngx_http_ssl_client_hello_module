
/*
 * Copyright (C) 2020-2020 ZengJinji
 */


#ifndef _NGX_HTTP_SSL_CLIENT_HELLO_H_INCLUDE_
#define _NGX_HTTP_SSL_CLIENT_HELLO_H_INCLUDE_


#define NGX_HTTP_SSL_CLIENT_HELLO_SUCCESS   SSL_CLIENT_HELLO_SUCCESS
#define NGX_HTTP_SSL_AD_NO_RENEGOTIATION    SSL_AD_NO_RENEGOTIATION


int ngx_http_ssl_client_hello_handler(ngx_ssl_conn_t *ssl_conn,
    int *al, void *arg);


#endif
