use POE;
use POE::Component::SSLify qw( Server_SSLify SSLify_Options );
use POE::Wheel::ReadWrite;
use POE::Wheel::SocketFactory;
use POE::Driver::SysRW;
use POE::Filter::Line;

# Needs to generate the SSL certs before running this!

POE::Session->new(
	'inline_states'	=>	{
		'_start'	=>	sub {
			# Okay, set the SSL options
			SSLify_Options( 'public-key.pem', 'public-cert.pem' );

			# Create the socketfactory wheel to listen for requests
			$_[HEAP]->{'SOCKETFACTORY'} = POE::Wheel::SocketFactory->new(
				'BindPort'	=>	5432,
				'BindAddress'	=>	localhost,
				'Reuse'		=>	'yes',
				'SuccessEvent'	=>	'Got_Connection',
				'FailureEvent'	=>	'ListenerError',
			);
			return;
		},
		'Got_Connection'	=>	sub {
			# ARG0 = Socket, ARG1 = Remote Address, ARG2 = Remote Port
			my $socket = $_[ ARG0 ];

			# SSLify it!
			$socket = Server_SSLify( $socket );

			# Hand it off to ReadWrite
			my $wheel = POE::Wheel::ReadWrite->new(
				'Handle'	=>	$socket,
				'Driver'	=>	POE::Driver::SysRW->new(),
				'Filter'	=>	POE::Filter::Line->new(),
				'InputEvent'	=>	'Got_Input',
				'FlushedEvent'	=>	'Got_Flush',
				'ErrorEvent'	=>	'Got_Error',
			);

			# Store it...
			$_[HEAP]->{'WHEELS'}->{ $wheel->ID } = $wheel;
			return;
		},
		'ListenerError'	=>	sub {
			# ARG0 = operation, ARG1 = error number, ARG2 = error string, ARG3 = wheel ID
			my ( $operation, $errnum, $errstr, $wheel_id ) = @_[ ARG0 .. ARG3 ];
			warn "SocketFactory Wheel $wheel_id generated $operation error $errnum: $errstr\n";

			return;
		},
		'Got_Input'	=>	sub {
			# ARG0: The Line, ARG1: Wheel ID

			# Send back to the client the line!
			$_[HEAP]->{'WHEELS'}->{ $_[ARG1] }->put( $_[ARG0] );
			return;
		},
		'Got_Flush'	=>	sub {
			# Done with a wheel
			delete $_[HEAP]->{'WHEELS'}->{ $_[ARG0] };
			return;
		},
		'Got_Error'	=>	sub {
			# ARG0 = operation, ARG1 = error number, ARG2 = error string, ARG3 = wheel ID
			my ( $operation, $errnum, $errstr, $id ) = @_[ ARG0 .. ARG3 ];
			warn "Wheel $id generated $operation error $errnum: $errstr\n";

			# Done with a wheel
			delete $_[HEAP]->{'WHEELS'}->{ $_[ARG0] };
			return;
		},
	},
);

# Start POE!
POE::Kernel->run();
exit 0;
