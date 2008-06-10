use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
	'NAME'			=> 'POE::Component::SSLify',
	'VERSION_FROM'		=> 'lib/POE/Component/SSLify.pm',
	'PREREQ_PM'		=>	{
		'Net::SSLeay'		=> '1.30',

		# test stuff
		'Test::More'		=> 0,
		'Test::Distribution'	=> 0,
		'Test::Strict'		=> 0,
		'Test::HasVersion'	=> 0,
		'Test::CheckManifest'	=> 0,
		'Test::Kwalitee'	=> 0,
		'Test::MinimumVersion'	=> 0,
		'Test::Pod'		=> 0,
		'Test::Pod::Coverage'	=> 0,
		'Test::UseAllModules'	=> 0,
	},
	(	$] >= 5.005 ?		# Add new keywords
		(
			'ABSTRACT_FROM'	=> 'lib/POE/Component/SSLify.pm', # retrieve abstract from module
			'AUTHOR'	=> 'Apocalypse <APOCAL@cpan.org>',
			'LICENSE'	=> 'perl',
		) : ()
	),
);
