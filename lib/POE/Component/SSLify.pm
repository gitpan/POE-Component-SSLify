# Declare our package
package POE::Component::SSLify;

# Standard stuff to catch errors
use strict qw(subs vars refs);				# Make sure we can't mess up
use warnings FATAL => 'all';				# Enable warnings to catch errors

# Initialize our version
use vars qw( $VERSION );
$VERSION = '0.01';

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
			require POE::Component::SSLify::Handle;
		}
	}
}

# Do the exporting magic...
require Exporter;
use vars qw( @ISA @EXPORT );
@ISA = qw( Exporter );
@EXPORT = qw( SSLify );

# Bring in some socket-related stuff
use Symbol qw( gensym );
use POSIX qw( F_GETFL F_SETFL O_NONBLOCK EAGAIN EWOULDBLOCK );

# Okay, the main routine here!
sub SSLify {
	# Get the socket!
	my $socket = shift;

	# Validation...
	if ( ! defined $socket ) {
		die "Did not get a defined socket";
	}

	# Net::SSLeay needs blocking for setup.
	#
	# ActiveState Perl 5.8.0 dislikes the Win32-specific code to make
	# a socket blocking, so we use IO::Handle's blocking(1) method.
	# Perl 5.005_03 doesn't like blocking(), so we only use it in
	# 5.8.0 and beyond.
	if ( $] >= 5.008 ) {
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

	# Now, we create the new socket and bind it to our subclass of Net::SSLeay::Handle
	my $newsock = gensym();
	tie( *$newsock, 'POE::Component::SSLify::Handle', $socket ) or die "Unable to tie to our subclass: $!";

	# All done!
	return $newsock;
}

# End of module
1;

__END__
=head1 NAME

POE::Component::SSLify - Makes using SSL in the world of POE easy!

=head1 SYNOPSIS

	# Import the module
	use POE::Component::SSLify;

	# Create a normal SocketFactory wheel or something
	my $factory = POE::Wheel::SocketFactory->new( ... );

	# Converts the socket into a SSL socket POE can communicate with
	eval { $socket = SSLify( $socket ) };
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

=head2 0.01

	Initial release

=head1 DESCRIPTION

This component represents the standard way to do SSL in POE.

The standard way to use this module is to do this:

	use POE::Component::SSLify;
	$sslsock = SSLify( $socket );

Oh, you want to set some SSL options? Then read up Net::SSLeay's POD and figure it out :)

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
		eval { $socket = SSLify( $socket ) };
		if ( $@ ) {
			# Unable to SSLify the socket...
		}
	}

=head2 Server SSL Sockets

This is not designed to be used in server/listening SSL sockets ( Because I haven't tested that ). Various POE
developers believe that in order to have a SSL server, you would need to set up a server certificate, among other
things. However, if this module magically works for you, let me know!

This module did not undergo "serious" testing, other than simple connections to verify that the SSL part works...

For further exploration, it is recommended to read the EXAMPLES section of Net::SSLeay's POD and study how they do
server sockets, I will work on this when I have the time, but patches are welcome :)

=head1 FUNCTIONS

	There's only one function: SSLify()

	Accepts a socket, SSLifies it, then returns a brand-new SSL-enabled socket!

	It might not be desirable, but SSLify() will die() if it is not able to do it's job...

=head1 EXPORT

	Exports one function by force: SSLify()

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