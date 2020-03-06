#!/usr/bin/perl

# (C) Zengjinji

# Tests for http ngx_http_ssl_ch_module.

###############################################################################

use warnings;
use strict;

use Test::More;

use Socket qw/ CRLF /;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

eval { require IO::Socket::SSL; };
plan(skip_all => 'IO::Socket::SSL not installed') if $@;
eval { IO::Socket::SSL::SSL_VERIFY_NONE(); };
plan(skip_all => 'IO::Socket::SSL too old') if $@;

my $t = Test::Nginx->new()->has(qw/http http_ssl/)
	->has_daemon('openssl')->plan(6);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    ssl_session_tickets off;
    ssl_session_cache none;

    ssl_client_hello on;

    server {
        listen       127.0.0.1:8081 ssl default;
        server_name  localhost;

        ssl_certificate_key localhost.key;
        ssl_certificate localhost.crt;
        ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
        ssl_ciphers ALL;

        location / {
            #return 200 $ssl_cipher;
            return 200 localhost_body;
        }
    }

    server {
        listen       127.0.0.1:8081 ssl;
        server_name  inner;

        ssl_certificate_key inner.key;
        ssl_certificate inner.crt;
        ssl_protocols TLSv1.2;
        ssl_ciphers ALL:!ECDHE;

        location / {
            return 200 inner_body;
        }
    }
}

EOF

$t->write_file('openssl.conf', <<EOF);
[ req ]
default_bits = 1024
encrypt_key = no
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
EOF

my $d = $t->testdir();

$t->write_file('ca.conf', <<EOF);
[ ca ]
default_ca = myca

[ myca ]
new_certs_dir = $d
database = $d/certindex
default_md = sha1
policy = myca_policy
serial = $d/certserial
default_days = 3

[ myca_policy ]
commonName = supplied
EOF

$t->write_file('certserial', '1000');
$t->write_file('certindex', '');

system('openssl req -x509 -new '
	. "-config $d/openssl.conf -subj /CN=issuer/ "
	. "-out $d/issuer.crt -keyout $d/issuer.key "
	. ">>$d/openssl.out 2>&1") == 0
	or die "Can't create certificate for issuer: $!\n";

system("openssl req -new "
	. "-config $d/openssl.conf -subj /CN=subject/ "
	. "-out $d/subject.csr -keyout $d/subject.key "
	. ">>$d/openssl.out 2>&1") == 0
	or die "Can't create certificate for subject: $!\n";

system("openssl ca -batch -config $d/ca.conf "
	. "-keyfile $d/issuer.key -cert $d/issuer.crt "
	. "-subj /CN=subject/ -in $d/subject.csr -out $d/subject.crt "
	. ">>$d/openssl.out 2>&1") == 0
	or die "Can't sign certificate for subject: $!\n";

foreach my $name ('localhost', 'inner') {
	system('openssl req -x509 -new '
		. "-config $d/openssl.conf -subj /CN=$name/ "
		. "-out $d/$name.crt -keyout $d/$name.key "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't create certificate for $name: $!\n";
}

open OLDERR, ">&", \*STDERR; close STDERR;
$t->run();
open STDERR, ">&", \*OLDERR;

###############################################################################
my $r;

$r = ssl_get('localhost', 'TLSv1_1', 'ALL');
like($r, qr/localhost_body/, 'localhost support TLSv1_1');

$r = ssl_get('localhost', 'TLSv1_2', 'ALL');
like($r, qr/localhost_body/, 'localhost support TLSv1_2');

$r = ssl_get('inner', 'TLSv1_1', 'ALL');
like($r, qr/alert protocol version/, 'inner no support TLSv1_1');

$r = ssl_get('inner', 'TLSv1_2', 'ALL');
like($r, qr/inner_body/, 'inner support TLSv1_2');


$r = ssl_get('localhost', 'TLSv1_2', 'ECDHE');
like($r, qr/localhost_body/, 'localhost support ECDHE');

$r = ssl_get('inner', 'TLSv1_2', 'ECDHE');
like($r, qr/alert handshake failure/, 'inner no support ECDHE');

###############################################################################

sub ssl_get {
	my ($sni, $version, $cipher_list) = @_;
	my $s;

	eval {
		local $SIG{ALRM} = sub { die "timeout\n" };
		local $SIG{PIPE} = sub { die "sigpipe\n" };
		alarm(5);
		$s = IO::Socket::SSL->new(
			Proto => 'tcp',
			PeerAddr => '127.0.0.1',
			PeerPort => port(8081),
			SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_NONE(),
			SSL_error_trap => sub { die $_[1] },
            SSL_hostname => $sni,
            SSL_version => $version,
            SSL_cipher_list => $cipher_list,

		);
		alarm(0);
	};
	alarm(0);

	if ($@) {
		#log_in("died: $@");
        #print "$@\n" if $@;
		return $@;
	}

	my $r = http(<<EOF, socket => $s);
GET / HTTP/1.0
Host: $sni

EOF

	$s->close();

    return $r;
}

###############################################################################
