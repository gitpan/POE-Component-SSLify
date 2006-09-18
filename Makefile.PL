use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
	'NAME'			=> 'POE::Component::SSLify',
	'VERSION_FROM'		=> 'lib/POE/Component/SSLify.pm',
	'PREREQ_PM'		=>	{
		'Net::SSLeay'		=>	'1.30',
	},
	(	$] >= 5.005 ?		# Add new keywords
		(
			'ABSTRACT_FROM'	=> 'lib/POE/Component/SSLify.pm', # retrieve abstract from module
			'AUTHOR'	=> 'Apocalypse <APOCAL@cpan.org>',
		) : ()
	),

	# Thanks POE!
	'dist'		=> {
		'PREOP'		=> (
			"echo 'license: perl' >> ./META.yml;" .
			'/bin/cp -f ./META.yml ./$(DISTNAME)-$(VERSION)/META.yml &2>/dev/null'
		),
	},
);
