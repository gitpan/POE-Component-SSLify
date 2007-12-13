# Declare our package
package POE::Component::SSLify::ClientHandle;

# Standard stuff to catch errors
use strict qw(subs vars refs);				# Make sure we can't mess up
use warnings FATAL => 'all';				# Enable warnings to catch errors

# Initialize our version
# $Revision: 1247 $
use vars qw( $VERSION );
$VERSION = '0.04';

# Import the SSL death routines
use Net::SSLeay qw( die_now die_if_ssl_error );

# We inherit from ServerHandle
use vars qw( @ISA );
@ISA = qw( POE::Component::SSLify::ServerHandle );

# Override TIEHANDLE because we create a CTX
sub TIEHANDLE {
	my ( $class, $socket, $version, $options ) = @_;

	my $ctx;
	if ( defined $version and ! ref $version ) {
		if ( $version eq 'sslv2' ) {
			$ctx = Net::SSLeay::CTX_v2_new();
		} elsif ( $version eq 'sslv3' ) {
			$ctx = Net::SSLeay::CTX_v3_new();
		} elsif ( $version eq 'tlsv1' ) {
			$ctx = Net::SSLeay::CTX_tlsv1_new();
		} elsif ( $version eq 'default' ) {
			$ctx = Net::SSLeay::CTX_new();
		} else {
			die "unknown SSL version: $version";
		}
	} else {
		$ctx = Net::SSLeay::CTX_new();
	}
	$ctx || die_now( "Failed to create SSL_CTX $!" );

	if ( defined $options ) {
		Net::SSLeay::CTX_set_options( $ctx, $options ) and die_if_ssl_error( 'ssl ctx set options' );
	}

	my $ssl = Net::SSLeay::new( $ctx ) or die_now( "Failed to create SSL $!" );

	my $fileno = fileno( $socket );

	Net::SSLeay::set_fd( $ssl, $fileno );   # Must use fileno

	my $resp = Net::SSLeay::connect( $ssl ) or die_if_ssl_error( 'ssl connect' );

	$POE::Component::SSLify::ServerHandle::Filenum_Object{ $fileno } = {
		ssl    => $ssl,
		ctx    => $ctx,
		socket => $socket,
	};

	return bless \$fileno, $class;
}

# Override close because it does not do CTX_Free, which is bad bad
sub CLOSE {
	my $self = shift;
	my $info = $self->_get_self();

	# Thanks to Eric Waters -> closes RT #22372
	if ( $info ) {
		Net::SSLeay::free( $info->{'ssl'} );
		Net::SSLeay::CTX_free( $info->{'ctx'} );
		close $info->{'socket'};
	}
	delete $POE::Component::SSLify::ServerHandle::Filenum_Object{ $$self };
	return 1;
}

# End of module
1;

__END__

=head1 NAME

POE::Component::SSLify::ClientHandle - client object for POE::Component::SSLify

=head1 ABSTRACT

	See POE::Component::SSLify

=head1 DESCRIPTION

	This is a subclass of Net::SSLeay::Handle because their read() and sysread()
	does not cooperate well with POE. They block until length bytes are read from the
	socket, and that is BAD in the world of POE...

	This subclass behaves exactly the same, except that it doesn't block :)

=head1 SEE ALSO

L<POE::Component::SSLify>

=head1 AUTHOR

Apocalypse E<lt>apocal@cpan.orgE<gt>

=head1 PROPS

	Original code is entirely Rocco Caputo ( Creator of POE ) -> I simply
	packaged up the code into something everyone could use...

	From the PoCo::Client::HTTP code =]
	# TODO - This code should probably become a POE::Kernel method,
    	# seeing as it's rather baroque and potentially useful in a number
    	# of places.

=head1 COPYRIGHT AND LICENSE

Copyright 2007 by Apocalypse/Rocco Caputo

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
