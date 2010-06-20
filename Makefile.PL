use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'POE::Filter::SSL',
    AUTHOR              => 'Markus Mueller <privi@cpan.org>',
    VERSION_FROM        => 'lib/POE/Filter/SSL.pm',
    ABSTRACT_FROM       => 'lib/POE/Filter/SSL.pm',
    PL_FILES            => {},
    LIBS		=> '-lssl',
    #TYPEMAPS		=> ['./typemap'],
    PREREQ_PM => {
        'Test::More' => 0,
        'Net::SSLeay'   => '1.32',
        'POE::Filter'   => 0,
        'XSLoader'      => 0
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'POE-Filter-SSL-*' },
);