use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
	'NAME'			=> 'POE::Component::SSLify',
	'VERSION_FROM'		=> 'lib/POE/Component/SSLify.pm',
	'PREREQ_PM'		=>	{
    	'Net::SSLeay'		=>	'1.17',
    	'Net::SSLeay::Handle'	=>	'0.61',
	},
	( $] >= 5.005 ?     ## Add these new keywords supported since 5.005
		('ABSTRACT_FROM'  => 'lib/POE/Component/SSLify.pm',
		'AUTHOR'         => 'Apocalypse <APOCAL@cpan.org>') : ()),
);
