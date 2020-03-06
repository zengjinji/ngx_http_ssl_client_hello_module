# ngx_http_ssl_client_hello_module

## Description

This module can allow different ssl_protocols and ssl_ciphers for different domain.



in nginx, it can not implement in one port, domain A support tlsv1.2, tlsv1.3 and domain B support tlsv1.2. like it:

```
http {
    server {
        listen 443 ssl default_server;
        ssl_protocols TLSv1.1 TLSv1.2 TLSv1.3;
        ssl_ciphers "EECDH+3DES:RSA+3DES:!MD5";
        ...
    }
     server {
        listen 443 ssl;
        server_name  b.com;
        ssl_protocols TLSv1.1 TLSv1.2;
        ssl_ciphers "!MD5";
        ...
    }
}
```

OpenSSL 1.1.1+ introduces SSL_CTX_set_client_hello_cb() . Through it can implement control ssl handshake protocols and ciphers by servename. 



**it need openssl more than 1.1.1**



## Installation

```
$ git clone git://github.com/zengjinji/ngx_http_ssl_client_hello_module.git
$ patch -p1 < ./ngx_http_ssl_client_hello_module/nginx_1.16.1+.patch
$ ./configure --with-http_ssl_module --add-module=./ngx_http_ssl_client_hello_module

```

## Directives

### ssl_client_hello

Syntax: **ssl_client_hello on|off**

Default: `off`

Context: `main`

It  allow different ssl_protocols and ssl_ciphers for different domain

## Example

file: conf/nginx.conf

```
http {
    ssl_client_hello on;
    server {
        listen 443 ssl default_server;
        ssl_protocols TLSv1.1 TLSv1.2 TLSv1.3;
        ssl_ciphers "EECDH+3DES:RSA+3DES:!MD5";
        location / {
            return 200 $ssl_cipher;
        }
    }
     server {
        listen 443 ssl;
        server_name  b.com;
        ssl_protocols TLSv1.1 TLSv1.2;
        ssl_ciphers "!MD5";
        location / {
            return 200 $ssl_cipher;
        }
    }
}
```

## Run Tests

```
$ git clone https://github.com/nginx/nginx-tests.git
$ TEST_NGINX_BINARY=/path/to/your/nginx/dir/sbin/nginx prove -I ./nginx-tests/lib ./t/ssl_client_hello.t
```
