use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'			=> 'Crypt::SaltedHash',
    'VERSION_FROM'	=> 'lib/Crypt/SaltedHash.pm', # finds $VERSION
    'PREREQ_PM'		=> {Digest => undef,}, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?    ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM => 'lib/Crypt/SaltedHash.pm', # retrieve abstract from module
       AUTHOR     => 'Sascha Kiefer <perl@intertivityNOSP4M.com>',
      ) : ()
    ),
);
