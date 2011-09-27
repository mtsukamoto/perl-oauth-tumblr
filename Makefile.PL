use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'OAuth::Tumblr',
    AUTHOR              => 'Makio Tsukamoto <tsukamoto@gmail.com>',
    VERSION_FROM        => 'lib/OAuth/Tumblr.pm',
    ABSTRACT_FROM       => 'lib/OAuth/Tumblr.pm',
    PL_FILES            => {},
    PREREQ_PM => {
        'Test::More'            => 0,
        'version'               => 0,
        'Class::ErrorHandler'   => 0,
        'Class::Accessor::Fast' => 0,
        'OAuth::Lite'           => 0,
        'CGI'                   => 0,
        'CGI::Session'          => 0,
        'File::Slurp'           => 0,
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'OAuth-Tumblr-*' },
);
