use ExtUtils::MakeMaker;

WriteMakefile(
    NAME         => 'Crypt::SaltedHash',
    VERSION_FROM => 'lib/Crypt/SaltedHash.pm',    # finds $VERSION
    PREREQ_PM => { 'MIME::Base64' => '3.05', 'Digest' => '1.08' },
    (
        $] >= 5.005
        ?    ## Add these new keywords supported since 5.005
          (
            ABSTRACT_FROM =>
              'lib/Crypt/SaltedHash.pm',    # retrieve abstract from module
            AUTHOR => 'Sascha Kiefer <esskar@cpan.org>'
          )
        : ()
    ),
);
