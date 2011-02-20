#
# This file is part of POE-Component-SSLify
#
# This software is copyright (c) 2011 by Apocalypse.
#
# This is free software; you can redistribute it and/or modify it under
# the same terms as the Perl 5 programming language system itself.
#
use strict; use warnings;
package POE::Component::SSLify;
BEGIN {
  $POE::Component::SSLify::VERSION = '1.002';
}
BEGIN {
  $POE::Component::SSLify::AUTHORITY = 'cpan:APOCAL';
}

# ABSTRACT: Makes using SSL in the world of POE easy!

# We need Net::SSLeay or all's a failure!
BEGIN {
	# We need >= 1.36 because it contains a lot of important fixes
	eval "use Net::SSLeay 1.36 qw( die_now die_if_ssl_error )";

	# Check for errors...
	if ( $@ ) {
		# Oh boy!
		die $@;
	} else {
		# Finally, load our subclasses :)
		# ClientHandle isa ServerHandle so it will get loaded automatically
		require POE::Component::SSLify::ClientHandle;

		# Initialize Net::SSLeay
		# Taken from http://search.cpan.org/~flora/Net-SSLeay-1.36/lib/Net/SSLeay.pm#Low_level_API
		Net::SSLeay::load_error_strings();
		Net::SSLeay::SSLeay_add_ssl_algorithms();
		# TODO do we need this?
		#Net::SSLeay::ENGINE_load_builtin_engines();  # If you want built-in engines
	        #Net::SSLeay::ENGINE_register_all_complete(); # If you want built-in engines
		Net::SSLeay::randomize();
	}
}

# Do the exporting magic...
require Exporter;
use vars qw( @ISA @EXPORT_OK );
@ISA = qw( Exporter );
@EXPORT_OK = qw( Client_SSLify Server_SSLify SSLify_Options SSLify_GetCTX SSLify_GetCipher SSLify_GetSocket SSLify_GetSSL SSLify_ContextCreate );

# Bring in some socket-related stuff
use Symbol qw( gensym );

# we need IO 1.24 for it's win32 fixes but it includes IO::Handle 1.27_02 which is dev...
# unfortunately we have to jump to IO 1.25 which includes IO::Handle 1.28... argh!
use IO::Handle 1.28;

# The server-side CTX stuff
my $ctx = undef;


sub Client_SSLify {
	# Get the socket + version + options + ctx
	my( $socket, $version, $options, $ctx ) = @_;

	# Validation...
	if ( ! defined $socket ) {
		die "Did not get a defined socket";
	}

	# From IO::Handle POD
	# If an error occurs blocking will return undef and $! will be set.
	if ( ! defined $socket->blocking( 0 ) ) {
		die "Unable to set nonblocking mode on socket: $!";
	}

	# Now, we create the new socket and bind it to our subclass of Net::SSLeay::Handle
	my $newsock = gensym();
	tie( *$newsock, 'POE::Component::SSLify::ClientHandle', $socket, $version, $options, $ctx ) or die "Unable to tie to our subclass: $!";

	# All done!
	return $newsock;
}


sub Server_SSLify {
	# Get the socket!
	my $socket = shift;
	my $custom_ctx = shift;

	# Validation...
	if ( ! defined $socket ) {
		die "Did not get a defined socket";
	}

	# If we don't have a ctx ready, we can't do anything...
	if ( ! defined $ctx and ! defined $custom_ctx ) {
		die 'Please do SSLify_Options() first ( or pass in a $ctx object )';
	}

	# From IO::Handle POD
	# If an error occurs blocking will return undef and $! will be set.
	if ( ! defined $socket->blocking( 0 ) ) {
		die "Unable to set nonblocking mode on socket: $!";
	}

	# Now, we create the new socket and bind it to our subclass of Net::SSLeay::Handle
	my $newsock = gensym();
	tie( *$newsock, 'POE::Component::SSLify::ServerHandle', $socket, ( $custom_ctx || $ctx ) ) or die "Unable to tie to our subclass: $!";

	# All done!
	return $newsock;
}


sub SSLify_ContextCreate {
	# Get the key + cert + version + options
	my( $key, $cert, $version, $options ) = @_;

	return _createSSLcontext( $key, $cert, $version, $options );
}


sub SSLify_Options {
	# Get the key + cert + version + options
	my( $key, $cert, $version, $options ) = @_;

	# sanity
	if ( ! defined $key or ! defined $cert ) {
		die 'no key/cert specified';
	}

	# Set the default
	if ( ! defined $options ) {
		$options = &Net::SSLeay::OP_ALL;
	}

	# set the context, possibly overwriting the previous one
	if ( defined $ctx ) {
		Net::SSLeay::CTX_free( $ctx );
		undef $ctx;
	}
	$ctx = _createSSLcontext( $key, $cert, $version, $options );

	# all done!
	return 1;
}

sub _createSSLcontext {
	my( $key, $cert, $version, $options ) = @_;

	my $context;
	if ( defined $version and ! ref $version ) {
		if ( $version eq 'sslv2' ) {
			$context = Net::SSLeay::CTX_v2_new();
		} elsif ( $version eq 'sslv3' ) {
			$context = Net::SSLeay::CTX_v3_new();
		} elsif ( $version eq 'tlsv1' ) {
			$context = Net::SSLeay::CTX_tlsv1_new();
		} elsif ( $version eq 'default' ) {
			$context = Net::SSLeay::CTX_new();
		} else {
			die "unknown SSL version: $version";
		}
	} else {
		$context = Net::SSLeay::CTX_new();
	}
	if ( ! defined $context ) {
		die_now( "Failed to create SSL_CTX $!" );
		return;
	}

	# do we need to set options?
	if ( defined $options ) {
		Net::SSLeay::CTX_set_options( $context, $options ) and die_if_ssl_error( 'ssl ctx set options' );
	}

	# do we need to set key/etc?
	if ( defined $key ) {
		# Following will ask password unless private key is not encrypted
		Net::SSLeay::CTX_use_RSAPrivateKey_file( $context, $key, &Net::SSLeay::FILETYPE_PEM );
		die_if_ssl_error( 'private key' );
	}

	# Set the cert file
	if ( defined $cert ) {
		Net::SSLeay::CTX_use_certificate_file( $context, $cert, &Net::SSLeay::FILETYPE_PEM );
		die_if_ssl_error( 'certificate' );
	}

	# All done!
	return $context;
}


sub SSLify_GetCTX {
	my $sock = shift;
	if ( ! defined $sock ) {
		return $ctx;
	} else {
		return tied( *$sock )->{'ctx'};
	}
}


sub SSLify_GetCipher {
	my $sock = shift;
	return Net::SSLeay::get_cipher( tied( *$sock )->{'ssl'} );
}


sub SSLify_GetSocket {
	my $sock = shift;
	return tied( *$sock )->{'socket'};
}


sub SSLify_GetSSL {
	my $sock = shift;
	return tied( *$sock )->{'ssl'};
}

1;


__END__
=pod

=head1 NAME

POE::Component::SSLify - Makes using SSL in the world of POE easy!

=head1 VERSION

  This document describes v1.002 of POE::Component::SSLify - released February 19, 2011 as part of POE-Component-SSLify.

=head1 SYNOPSIS

	# CLIENT-side usage

	# Import the module
	use POE::Component::SSLify qw( Client_SSLify );

	# Create a normal SocketFactory wheel and connect to a SSL-enabled server
	my $factory = POE::Wheel::SocketFactory->new;

	# Time passes, SocketFactory gives you a socket when it connects in SuccessEvent
	# Convert the socket into a SSL socket POE can communicate with
	my $socket = shift;
	eval { $socket = Client_SSLify( $socket ) };
	if ( $@ ) {
		# Unable to SSLify it...
	}

	# Now, hand it off to ReadWrite
	my $rw = POE::Wheel::ReadWrite->new(
		Handle	=>	$socket,
		# other options as usual
	);

	# --------------------------------------------------------------------------- #

	# SERVER-side usage

	# !!! Make sure you have a public key + certificate
	# excellent howto: http://www.akadia.com/services/ssh_test_certificate.html

	# Import the module
	use POE::Component::SSLify qw( Server_SSLify SSLify_Options );

	# Set the key + certificate file
	eval { SSLify_Options( 'server.key', 'server.crt' ) };
	if ( $@ ) {
		# Unable to load key or certificate file...
	}

	# Create a normal SocketFactory wheel to listen for connections
	my $factory = POE::Wheel::SocketFactory->new;

	# Time passes, SocketFactory gives you a socket when it gets a connection in SuccessEvent
	# Convert the socket into a SSL socket POE can communicate with
	my $socket = shift;
	eval { $socket = Server_SSLify( $socket ) };
	if ( $@ ) {
		# Unable to SSLify it...
	}

	# Now, hand it off to ReadWrite
	my $rw = POE::Wheel::ReadWrite->new(
		Handle	=>	$socket,
		# other options as usual
	);

=head1 DESCRIPTION

This component represents the standard way to do SSL in POE.

=head1 FUNCTIONS

=head2 Client_SSLify

	Accepts a socket, returns a brand new socket SSLified. Optionally accepts SSL
	context data.
		my $socket = shift;						# get the socket from somewhere
		$socket = Client_SSLify( $socket );				# the default
		$socket = Client_SSLify( $socket, $version, $options );		# sets more options for the context
		$socket = Client_SSLify( $socket, undef, undef, $ctx );		# pass in a custom context

	If $ctx is defined, SSLify will ignore other args. If $ctx isn't defined, SSLify
	will create it from the $version + $options parameters.

	Known versions:
		* sslv2
		* sslv3
		* tlsv1
		* default

	By default we use the version: default

	By default we don't set any options

	NOTE: The way to have a client socket with proper certificates set up is:
		my $socket = shift;	# get the socket from somewhere
		my $ctx = SSLify_ContextCreate( 'server.key', 'server.crt' );
		$socket = Client_SSLify( $socket, undef, undef, $ctx );

	BEWARE: If you passed in a CTX, SSLify will do Net::SSLeay::CTX_free( $ctx ) when the
	socket is destroyed. This means you cannot reuse contexts!

=head2 Server_SSLify

	Accepts a socket, returns a brand new socket SSLified
		my $socket = shift;	# get the socket from somewhere
		$socket = Server_SSLify( $socket );

	NOTE: SSLify_Options must be set first!

	Furthermore, you can pass in your own $ctx object if you desire. This allows you to set custom parameters
	per-connection, for example.
		my $socket = shift;	# get the socket from somewhere
		my $ctx = SSLify_ContextCreate();
		# set various options on $ctx as desired
		$socket = Server_SSLify( $socket, $ctx );

	NOTE: You can use SSLify_GetCTX to modify the global, and avoid doing this on every connection if the
	options are the same...

=head2 SSLify_ContextCreate

	Accepts some options, and returns a brand-new Net::SSLeay context object ( $ctx )
		my $ctx = SSLify_ContextCreate( $key, $cert, $version, $options );

	You can then call various Net::SSLeay methods on the context
		my $mode = Net::SSLeay::CTX_get_mode( $ctx );

	By default we don't use the SSL key + certificate files

	By default we use the version: default

		Known versions:
		* sslv2
		* sslv3
		* tlsv1
		* default

	By default we don't set any options

=head2 SSLify_Options

	Call this function to initialize the global server-side CTX. Accepts the location of the
	SSL key + certificate files, which is required.

	Optionally accepts the SSL version + CTX options
		SSLify_Options( $key, $cert, $version, $options );

	By default we use the version: default

		Known versions:
		* sslv2
		* sslv3
		* tlsv1
		* default

	By default we use the options: &Net::SSLeay::OP_ALL

=head2 SSLify_GetCTX

	Returns the actual Net::SSLeay context object in case you wanted to play with it :)

	If passed in a socket, it will return that socket's $ctx instead of the global.
		my $ctx = SSLify_GetCTX();			# get the one set via SSLify_Options
		my $ctx = SSLify_GetCTX( $sslified_sock );	# get the one in the object

=head2 SSLify_GetCipher

	Returns the cipher used by the SSLified socket

	Example:
		print "SSL Cipher is: " . SSLify_GetCipher( $sslified_sock ) . "\n";

	NOTE: Doing this immediately after Client_SSLify or Server_SSLify will result in "(NONE)" because the SSL handshake
	is not done yet. The socket is nonblocking, so you will have to wait a little bit for it to get ready.
		apoc@blackhole:~/mygit/perl-poe-sslify/examples$ perl serverclient.pl
		got connection from: 127.0.0.1 - commencing Server_SSLify()
		SSLified: 127.0.0.1 cipher type: ((NONE))
		Connected to server, commencing Client_SSLify()
		SSLified the connection to the server
		Connected to SSL server
		Input: hola
		got input from: 127.0.0.1 cipher type: (AES256-SHA) input: 'hola'
		Got Reply: hola
		Input: ^C
		stopped at serverclient.pl line 126.

=head2 SSLify_GetSocket

	Returns the actual socket used by the SSLified socket, useful for stuff like getpeername()/getsockname()

	Example:
		print "Remote IP is: " . inet_ntoa( ( unpack_sockaddr_in( getpeername( SSLify_GetSocket( $sslified_sock ) ) ) )[1] ) . "\n";

=head2 SSLify_GetSSL

	Returns the actual Net::SSLeay object so you can call methods on it

	Example:
		print Net::SSLeay::dump_peer_certificate( SSLify_GetSSL( $sslified_sock ) );

=head1 NOTES

=head2 Socket methods doesn't work

The new socket this module gives you actually is some tied socket magic, so you cannot do stuff like
getpeername() or getsockname(). The only way to do it is to use SSLify_GetSocket and then operate on
the socket it returns.

=head2 Dying everywhere...

This module will die() if Net::SSLeay could not be loaded or it is not the version we want. So, it is recommended
that you check for errors and not use SSL, like so:

	eval { use POE::Component::SSLify };
	if ( $@ ) {
		$sslavailable = 0;
	} else {
		$sslavailable = 1;
	}

	# Make socket SSL!
	if ( $sslavailable ) {
		eval { $socket = POE::Component::SSLify::Client_SSLify( $socket ) };
		if ( $@ ) {
			# Unable to SSLify the socket...
		}
	}

=head2 OpenSSL functions

Theoretically you can do anything that Net::SSLeay exports from the OpenSSL libs on the socket. However, I have not tested every
possible function against SSLify, so use them carefully!

=head3 Net::SSLeay::renegotiate

This function has been tested ( it's in C<t/2_renegotiate.t> ) but it doesn't work on FreeBSD! I tracked it down to this security advisory:
L<http://security.freebsd.org/advisories/FreeBSD-SA-09:15.ssl.asc> which explains it in detail. The test will skip this function
if it detects that you're on a broken system. However, if you have the updated OpenSSL library that fixes this you can use it.

=head3 In-Situ sslification

You can have a normal plaintext socket, and convert it to SSL anytime. Just keep in mind that the client and the server must agree to sslify
at the same time, or they will be waiting on each other forever! See C<t/3_insitu.t> for an example of how this works.

=head1 EXPORT

	Stuffs all of the above functions in @EXPORT_OK so you have to request them directly

=head1 SEE ALSO

Please see those modules/websites for more information related to this module.

=over 4

=item *

L<POE>

=item *

L<Net::SSLeay>

=back

=for :stopwords cpan testmatrix url annocpan anno bugtracker rt cpants kwalitee diff irc mailto metadata placeholders

=head1 SUPPORT

=head2 Perldoc

You can find documentation for this module with the perldoc command.

  perldoc POE::Component::SSLify

=head2 Websites

The following websites have more information about this module, and may be of help to you. As always,
in addition to those websites please use your favorite search engine to discover more resources.

=over 4

=item *

Search CPAN

L<http://search.cpan.org/dist/POE-Component-SSLify>

=item *

RT: CPAN's Bug Tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=POE-Component-SSLify>

=item *

AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/POE-Component-SSLify>

=item *

CPAN Ratings

L<http://cpanratings.perl.org/d/POE-Component-SSLify>

=item *

CPAN Forum

L<http://cpanforum.com/dist/POE-Component-SSLify>

=item *

CPANTS Kwalitee

L<http://cpants.perl.org/dist/overview/POE-Component-SSLify>

=item *

CPAN Testers Results

L<http://cpantesters.org/distro/P/POE-Component-SSLify.html>

=item *

CPAN Testers Matrix

L<http://matrix.cpantesters.org/?dist=POE-Component-SSLify>

=back

=head2 Email

You can email the author of this module at C<APOCAL at cpan.org> asking for help with any problems you have.

=head2 Internet Relay Chat

You can get live help by using IRC ( Internet Relay Chat ). If you don't know what IRC is,
please read this excellent guide: L<http://en.wikipedia.org/wiki/Internet_Relay_Chat>. Please
be courteous and patient when talking to us, as we might be busy or sleeping! You can join
those networks/channels and get help:

=over 4

=item *

irc.perl.org

You can connect to the server at 'irc.perl.org' and join this channel: #perl-help then talk to this person for help: Apocalypse.

=item *

irc.freenode.net

You can connect to the server at 'irc.freenode.net' and join this channel: #perl then talk to this person for help: Apocal.

=item *

irc.efnet.org

You can connect to the server at 'irc.efnet.org' and join this channel: #perl then talk to this person for help: Ap0cal.

=back

=head2 Bugs / Feature Requests

Please report any bugs or feature requests by email to C<bug-poe-component-sslify at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=POE-Component-SSLify>. You will be automatically notified of any
progress on the request by the system.

=head2 Source Code

The code is open to the world, and available for you to hack on. Please feel free to browse it and play
with it, or whatever. If you want to contribute patches, please send me a diff or prod me to pull
from your repository :)

L<http://github.com/apocalypse/perl-poe-sslify>

  git clone git://github.com/apocalypse/perl-poe-sslify.git

=head1 AUTHOR

Apocalypse <APOCAL@cpan.org>

=head1 ACKNOWLEDGEMENTS

	Original code is entirely Rocco Caputo ( Creator of POE ) -> I simply
	packaged up the code into something everyone could use and accepted the burden
	of maintaining it :)

	From the PoCo::Client::HTTP code =]
	# This code should probably become a POE::Kernel method,
    	# seeing as it's rather baroque and potentially useful in a number
    	# of places.

ASCENT also helped a lot with the nonblocking mode, without his hard work this
module would still be stuck in the stone age :)

=head1 COPYRIGHT AND LICENSE

This software is copyright (c) 2011 by Apocalypse.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.

The full text of the license can be found in the LICENSE file included with this distribution.

=cut

