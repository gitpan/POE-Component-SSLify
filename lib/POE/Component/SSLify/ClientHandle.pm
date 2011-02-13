#
# This file is part of POE-Component-SSLify
#
# This software is copyright (c) 2011 by Apocalypse.
#
# This is free software; you can redistribute it and/or modify it under
# the same terms as the Perl 5 programming language system itself.
#
use strict; use warnings;
package POE::Component::SSLify::ClientHandle;
BEGIN {
  $POE::Component::SSLify::ClientHandle::VERSION = '1.000';
}
BEGIN {
  $POE::Component::SSLify::ClientHandle::AUTHORITY = 'cpan:APOCAL';
}

# ABSTRACT: Client-side handle for SSLify

# Import the SSL death routines
use Net::SSLeay qw( die_now die_if_ssl_error );

# We inherit from ServerHandle
use vars qw( @ISA );
require POE::Component::SSLify::ServerHandle;
@ISA = qw( POE::Component::SSLify::ServerHandle );

# Override TIEHANDLE because we create a CTX
sub TIEHANDLE {
	my ( $class, $socket, $version, $options, $ctx ) = @_;

	# create a context, if necessary
	if ( ! defined $ctx ) {
		$ctx = POE::Component::SSLify::_createSSLcontext( undef, undef, $version, $options );
	}

	my $ssl = Net::SSLeay::new( $ctx ) or die_now( "Failed to create SSL $!" );

	my $fileno = fileno( $socket );

	Net::SSLeay::set_fd( $ssl, $fileno );   # Must use fileno

	# Socket is in non-blocking mode, so connect() will return immediately.
	# die_if_ssl_error won't die on non-blocking errors. We don't need to call connect()
	# again, because OpenSSL I/O functions (read, write, ...) can handle that entirely
	# by self (it's needed to connect() once to determine connection type).
	my $resp = Net::SSLeay::connect( $ssl ) or die_if_ssl_error( 'ssl connect' );

	my $self = bless {
		'ssl'		=> $ssl,
		'ctx'		=> $ctx,
		'socket'	=> $socket,
		'fileno'	=> $fileno,
		'client'	=> 1,
	}, $class;

	return $self;
}

1;


__END__
=pod

=head1 NAME

POE::Component::SSLify::ClientHandle - Client-side handle for SSLify

=head1 VERSION

  This document describes v1.000 of POE::Component::SSLify::ClientHandle - released February 12, 2011 as part of POE-Component-SSLify.

=head1 DESCRIPTION

	This is a subclass of ServerHandle to accomodate clients setting custom context objects.

=head1 SEE ALSO

Please see those modules/websites for more information related to this module.

=over 4

=item *

L<POE::Component::SSLify>

=item *

L<POE::Component::SSLify::ServerHandle>

=back

=head1 AUTHOR

Apocalypse <APOCAL@cpan.org>

=head1 COPYRIGHT AND LICENSE

This software is copyright (c) 2011 by Apocalypse.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.

The full text of the license can be found in the LICENSE file included with this distribution.

=cut

