
use strict;
use warnings;

use Module::Build 0.3601;


my %module_build_args = (
  'build_requires' => {
    'File::Find' => '0',
    'File::Temp' => '0',
    'Module::Build' => '0.3601',
    'POE' => '1.267',
    'POE::Component::Client::TCP' => '0',
    'POE::Component::Server::TCP' => '0',
    'Socket' => '0',
    'Test::More' => '0.88'
  },
  'configure_requires' => {
    'Module::Build' => '0.3601'
  },
  'dist_abstract' => 'Makes using SSL in the world of POE easy!',
  'dist_author' => [
    'Apocalypse <APOCAL@cpan.org>'
  ],
  'dist_name' => 'POE-Component-SSLify',
  'dist_version' => '1.004',
  'license' => 'perl',
  'module_name' => 'POE::Component::SSLify',
  'recommends' => {},
  'recursive_test_files' => 1,
  'requires' => {
    'Exporter' => '0',
    'IO::Handle' => '1.28',
    'Net::SSLeay' => '1.36',
    'Scalar::Util' => '0',
    'Symbol' => '0',
    'Task::Weaken' => '1.03',
    'parent' => '0',
    'perl' => '5.006'
  },
  'script_files' => []
);


my $build = Module::Build->new(%module_build_args);

$build->create_build_script;
