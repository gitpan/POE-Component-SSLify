# Declare our package
package POE::Component::SSLify::ServerHandle;

# Standard stuff to catch errors
use strict qw(subs vars refs);				# Make sure we can't mess up
use warnings FATAL => 'all';				# Enable warnings to catch errors

# Initialize our version
use vars qw( $VERSION );
$VERSION = '0.01';

# Import the SSL death routines
use Net::SSLeay qw( die_now die_if_ssl_error );

# Argh, we actually copy over some stuff
my %Filenum_Object;    #-- hash of hashes, keyed by fileno()

# Override TIEHANDLE because now we use the server CTX
sub TIEHANDLE {
	my ( $class, $socket, $ctx ) = @_;

	my $ssl = Net::SSLeay::new( $ctx ) or die_now( "Failed to create SSL $!" );

	my $fileno = fileno( $socket );

	Net::SSLeay::set_fd( $ssl, $fileno );

	my $err = Net::SSLeay::accept( $ssl ) and die_if_ssl_error( 'ssl accept' );

	$Filenum_Object{ $fileno } = {
		ssl    => $ssl,
		ctx    => $ctx,
		socket => $socket,
		fileno => $fileno,
	};

	return bless $socket, $class;
}

# Override the read stuff
sub READ {
	# Get the pointers to socket, buffer, length, and the offset
	my( $sock, $buf, $len, $offset ) = \( @_ );

	# Get the actual ssl handle
	my $ssl = $Filenum_Object{ fileno( $$sock ) }->{'ssl'};

	# If we have no offset, replace the buffer with some input
	if ( ! defined $$offset ) {
		$$buf = Net::SSLeay::read( $ssl, $$len );

		# Are we done?
		if ( defined $$buf ) {
			return length( $$buf );
		} else {
			# Nah, clear the buffer too...
			$$buf = "";
			return;
		}
	}

	# Now, actually read the data
	defined( my $read = Net::SSLeay::read( $ssl, $$len ) ) or return undef;

	# Figure out the buffer and offset
	my $buf_len = length( $$buf );

	# If our offset is bigger, pad the buffer
	if ( $$offset > $buf_len ) {
		$$buf .= chr( 0 ) x ( $$offset - $buf_len );
	}

	# Insert what we just read into the buffer
	substr( $$buf, $$offset ) = $read;

	# All done!
	return length( $read );
}

# Override the write stuff
sub WRITE {
	# Get the socket + buffer + length + offset to write
	my( $sock, $buf, $len, $offset ) = @_;

	# If we have nothing to offset, then start from the beginning
	if ( ! defined $offset ) {
		$offset = 0;
	}

	# Okay, get the ssl handle
	my $ssl = $Filenum_Object{ fileno( $sock ) }->{'ssl'};

	# We count the number of characters written to the socket
	my $wrote_len = Net::SSLeay::write( $ssl, substr( $buf, $offset, $len ) );

	# Did we get an error or number of bytes written?
	# Net::SSLeay::write() returns the number of bytes written, or -1 on error.
	if ( $wrote_len < 0 ) {
		# The normal syswrite() POE uses expects 0 here.
		return 0;
	} else {
		# All done!
		return $wrote_len;
	}
}

# Override close because it does CTX_Free, which is bad bad
sub CLOSE {
	my $sock = shift;
	Net::SSLeay::free( $Filenum_Object{ fileno( $sock ) }->{'ssl'} );
	delete $Filenum_Object{ fileno( $sock ) };
	close $sock;
}

sub FILENO {
	my $sock = shift;
	return fileno( $sock );
}

# Not implemented TIE's
sub READLINE {
	die 'Not Implemented';
}

sub PRINT {
	die 'Not Implemented';
}

# Our own convenience functions
sub _CIPHER {
	my $sock = shift;
	return Net::SSLeay::get_cipher( $Filenum_Object{ fileno( $sock ) }->{'ssl'} );
}

# End of module
1;

__END__
=head1 NAME

POE::Component::SSLify::ServerHandle

=head1 ABSTRACT

	See POE::Component::SSLify

=head1 CHANGES

=head2 0.01

	Initial release

=head1 DESCRIPTION

	This is a subclass of Net::SSLeay::Handle because their read() and sysread()
	does not cooperate well with POE. They block until length bytes are read from the
	socket, and that is BAD in the world of POE...

	This subclass behaves exactly the same, except that it doesn't block :)

=head2 DIFFERENCES

	This subclass doesn't know what to do with PRINT/READLINE, as they usually are not used in POE::Wheel operations...

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

Copyright 2004 by Apocalypse/Rocco Caputo

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut