# Declare our package
package POE::Component::SSLify;

# Standard stuff to catch errors
use strict qw(subs vars refs);				# Make sure we can't mess up
use warnings FATAL => 'all';				# Enable warnings to catch errors

# Initialize our version
use vars qw( $VERSION );
$VERSION = '0.03';

# We need Net::SSLeay or all's a failure!
BEGIN {
	eval { require Net::SSLeay::Handle };

	# Check for errors...
	if ( $@ ) {
		# Oh boy!
		die $@;
	} else {
		# Check to make sure the versions are what we want
		if ( ! (	defined $Net::SSLeay::VERSION and
				defined $Net::SSLeay::Handle::VERSION and
				$Net::SSLeay::VERSION >= 1.17 and
				$Net::SSLeay::Handle::VERSION >= 0.61 ) ) {
			# Argh...
			die 'Please upgrade Net::SSLeay to 1.17+ or Net::SSLeay::Handle to 0.61+';
		} else {
			# Finally, load our subclass :)
			require POE::Component::SSLify::ClientHandle;
			require POE::Component::SSLify::ServerHandle;
		}
	}
}

# Do the exporting magic...
require Exporter;
use vars qw( @ISA @EXPORT_OK );
@ISA = qw( Exporter );
@EXPORT_OK = qw( Client_SSLify Server_SSLify SSLify_Options SSLify_GetCTX );

# Bring in some socket-related stuff
use Symbol qw( gensym );
use POSIX qw( F_GETFL F_SETFL O_NONBLOCK EAGAIN EWOULDBLOCK );

# We need the server-side stuff
use Net::SSLeay qw( die_now die_if_ssl_error );

# The server-side CTX stuff
my $ctx = undef;

# Helper sub to set blocking on a handle
sub Set_Blocking {
	my $socket = shift;

	# Net::SSLeay needs blocking for setup.
	#
	# ActiveState Perl 5.8.0 dislikes the Win32-specific code to make
	# a socket blocking, so we use IO::Handle's blocking(1) method.
	# Perl 5.005_03 doesn't like blocking(), so we only use it in
	# 5.8.0 and beyond.
	if ( $] >= 5.008 and $^O eq 'MSWin32' ) {
		# From IO::Handle POD
		# If an error occurs blocking will return undef and $! will be set.
		if ( ! $socket->blocking( 1 ) ) {
			die "Unable to set blocking mode on socket: $!";
		}
	} else {
		# Make the handle blocking, the POSIX way.
		if ( $^O ne 'MSWin32' ) {
			# Get the old flags
			my $flags = fcntl( $socket, F_GETFL, 0 ) or die "fcntl( $socket, F_GETFL, 0 ) fails: $!";

			# Okay, we patiently wait until the socket turns blocking mode
			until( fcntl( $socket, F_SETFL, $flags & ~O_NONBLOCK ) ) {
				# What was the error?
				if ( ! ( $! == EAGAIN or $! == EWOULDBLOCK ) ) {
					# Fatal error...
					die "fcntl( $socket, FSETFL, etc ) fails: $!";
				}
			}
		} else {
			# Darned MSWin32 way...
			# Do some ioctl magic here
			# 126 is FIONBIO ( some docs say 0x7F << 16 )
			my $flag = "0";
			ioctl( $socket, 0x80000000 | ( 4 << 16 ) | ( ord( 'f' ) << 8 ) | 126, $flag ) or die "ioctl( $socket, FIONBIO, $flag ) fails: $!";
		}
	}

	# All done!
	return $socket;
}

# Okay, the main routine here!
sub Client_SSLify {
	# Get the socket!
	my $socket = shift;

	# Validation...
	if ( ! defined $socket ) {
		die "Did not get a defined socket";
	}

	# Set blocking on
	$socket = Set_Blocking( $socket );

	# Now, we create the new socket and bind it to our subclass of Net::SSLeay::Handle
	my $newsock = gensym();
	tie( *$newsock, 'POE::Component::SSLify::ClientHandle', $socket ) or die "Unable to tie to our subclass: $!";

	# All done!
	return $newsock;
}

# Okay, the main routine here!
sub Server_SSLify {
	# Get the socket!
	my $socket = shift;

	# Validation...
	if ( ! defined $socket ) {
		die "Did not get a defined socket";
	}

	# If we don't have a ctx ready, we can't do anything...
	if ( ! defined $ctx ) {
		die 'Please do SSLify_Options() first';
	}

	# Set blocking on
	$socket = Set_Blocking( $socket );

	# Now, we create the new socket and bind it to our subclass of Net::SSLeay::Handle
	my $newsock = gensym();
	tie( *$newsock, 'POE::Component::SSLify::ServerHandle', $socket, $ctx ) or die "Unable to tie to our subclass: $!";

	# All done!
	return $newsock;
}

# Sets the key + certificate
sub SSLify_Options {
	# Get the key + cert
	my( $key, $cert ) = @_;

	Net::SSLeay::Handle->_initialize();

	$ctx = Net::SSLeay::CTX_new() or die_now( "CTX_new($ctx): $!" );
	Net::SSLeay::CTX_set_options( $ctx, &Net::SSLeay::OP_ALL ) and die_if_ssl_error( 'ssl ctx set options' );

	# Following will ask password unless private key is not encrypted
	Net::SSLeay::CTX_use_RSAPrivateKey_file( $ctx, $key, &Net::SSLeay::FILETYPE_PEM );
	die_if_ssl_error( 'private key' );

	# Set the cert file
	Net::SSLeay::CTX_use_certificate_file( $ctx, $cert, &Net::SSLeay::FILETYPE_PEM );
	die_if_ssl_error( 'certificate' );

	# All done!
	return 1;
}

# Returns the server-side CTX in case somebody wants to play with it
sub SSLify_GetCTX {
	return $ctx;
}

# End of module
1;

__END__
=head1 NAME

POE::Component::SSLify - Makes using SSL in the world of POE easy!

=head1 SYNOPSIS

=head2 Client-side usage

	# Import the module
	use POE::Component::SSLify qw( Client_SSLify );

	# Create a normal SocketFactory wheel or something
	my $factory = POE::Wheel::SocketFactory->new( ... );

	# Converts the socket into a SSL socket POE can communicate with
	eval { $socket = Client_SSLify( $socket ) };
	if ( $@ ) {
		# Unable to SSLify it...
	}

	# Now, hand it off to ReadWrite
	my $rw = POE::Wheel::ReadWrite->new(
		Handle	=>	$socket,
		...
	);

	# Use it as you wish...

=head2 Server-side usage

	# !!! Make sure you have a public key + certificate generated via Net::SSLeay's makecert.pl

	# Import the module
	use POE::Component::SSLify qw( Server_SSLify SSLify_Options SSLify_GetCTX );

	# Set the key + certificate file
	eval { SSLify_Options( 'public-key.pem', 'public-cert.pem' ) };
	if ( $@ ) {
		# Unable to load key or certificate file...
	}

	# Ah, I want to set some options ( not required )
	# my $ctx = SSLify_GetCTX();
	# Net::SSLeay::CTX_set_options( $ctx, foo );

	# Create a normal SocketFactory wheel or something
	my $factory = POE::Wheel::SocketFactory->new( ... );

	# Converts the socket into a SSL socket POE can communicate with
	eval { $socket = Server_SSLify( $socket ) };
	if ( $@ ) {
		# Unable to SSLify it...
	}

	# Now, hand it off to ReadWrite
	my $rw = POE::Wheel::ReadWrite->new(
		Handle	=>	$socket,
		...
	);

	# Use it as you wish...

=head1 ABSTRACT

	Makes SSL use in POE a breeze!

=head1 CHANGES

=head2 0.03

	First stab at the server-side code, help me test it out!
	Refactored SSLify() into client/server side, so update your program accordingly!

=head2 0.02

	Made sure the IO::Handle way was used only on MSWin32

=head2 0.01

	Initial release

=head1 DESCRIPTION

This component represents the standard way to do SSL in POE.



=head1 NOTES

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

=head1 FUNCTIONS

	There's four functions one can use:

=head2 Client_SSLify

	Accepts a socket, returns a brand new socket SSLified

=head2 Server_SSLify

	Accepts a socket, returns a brand new socket SSLified

	NOTE: SSLify_Options must be set first!

=head2 SSLify_Options

	Accepts the location of the SSL key + certificate files and does it's job

=head2 SSLify_GetCTX

	Returns the server-side CTX in case you wanted to play around with it :)

=head1 EXPORT

	Stuffs all the 4 functions in @EXPORT_OK so you have to request them directly

=head1 SEE ALSO

L<POE>

L<Net::SSLeay>

=head1 AUTHOR

Apocalypse E<lt>apocal@cpan.orgE<gt>

=head1 PROPS

	Original code is entirely Rocco Caputo ( Creator of POE ) -> I simply
	packaged up the code into something everyone could use and accepted the burden
	of maintaining it :)

	From the PoCo::Client::HTTP code =]
	# TODO - This code should probably become a POE::Kernel method,
    	# seeing as it's rather baroque and potentially useful in a number
    	# of places.

=head1 COPYRIGHT AND LICENSE

Copyright 2004 by Apocalypse/Rocco Caputo

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut