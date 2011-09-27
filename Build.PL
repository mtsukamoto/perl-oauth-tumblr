use strict;
use warnings;
use Module::Build;

my $builder = Module::Build->new(
    module_name         => 'OAuth::Tumblr',
    license             => 'perl',
    dist_author         => 'Makio Tsukamoto <tsukamoto@gmail.com>',
    dist_version_from   => 'lib/OAuth/Tumblr.pm',
    requires => {
        'Test::More' => 0,
        'version'    => 0,
    },
    add_to_cleanup      => [ 'OAuth-Tumblr-*' ],
);

$builder->create_build_script();
