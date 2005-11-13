package Crypt::SaltedHash;

use strict;
use MIME::Base64 ();
use Digest       ();

use vars qw($VERSION);

$VERSION = '0.01';

=head1 NAME

Crypt::SaltedHash - Perl interface to functions that will assist in working
with salted hashes.

=head1 SYNOPSIS

	use Crypt::SaltedHash;

	my $csh = Crypt::SaltedHash->new(algorithm => 'SHA-1');
	$csh->add('secret');

	my $salted = $csh->generate;
	my $valid = Crypt::SaltedHash->validate($salted, 'secret');


=head1 DESCRIPTION

The C<Crypt::SaltedHash> module provides an object oriented interface to
create salted (or seeded) hashed of clear text data. The original
formalization of this concept comes from RFC-3112 and is extended by the use
of different digital agorithms.

=head1 METHODS

=over 4

=item B<new([%options])>

Returns a new Crypt::SaltedHash object.
Possible keys for I<%options> are:

- I<algorithm>: It's also possible to use common string representations of the
algorithm (e.g. "sha256", "SHA-384"). If the argument is missing, SHA-1 will
be used by default.

=cut

sub new {
    my ( $class, %options ) = @_;

    $options{algorithm} ||= 'SHA-1';
    $options{salt}      ||= &generate_hex_salt();

    $options{algorithm} = uc( $options{algorithm} );
    $options{algorithm} = 'SHA' if $options{algorithm} eq 'SHA-1';

    my $algorithm = $options{algorithm};
    $algorithm = 'SHA-1' if $algorithm eq 'SHA';

    my $digest = Digest->new($algorithm);
    my $self   = {
        salt      => $options{salt},
        algorithm => $options{algorithm},
        digest    => $digest,
        scheme    => &make_scheme( $options{algorithm} ),
    };

    return bless $self, $class;
}

=item B<obj()>

=cut

sub obj {
    shift->{digest};
}

=item B<add($data, ...)>

Logically joins the arguments into a single string, and uses it to
update the current digest state. For more details see L<Digest>.

=cut

sub add {
    my $self = shift;
    $self->obj->add(@_);
}

=item B<generate()>

=cut

sub generate {
    my ($self) = @_;

    my $clone = $self->obj->clone;
    my $salt  = pack( "H*", $self->{salt} );

    $clone->add($salt);

    my $gen    = &MIME::Base64::encode_base64( $clone->digest . $salt, '' );
    my $scheme = $self->{scheme};

    return "{$scheme}$gen";
}

=item B<validate($hasheddata, $cleardata)>

=cut

sub validate {
    my ( undef, $hasheddata, $cleardata ) = @_;

    my $scheme    = uc( &get_pass_scheme($hasheddata) );
    my $algorithm = &make_algorithm($scheme);
    my $salt      = &extract_salt( &get_pass_hash($hasheddata) );

    my $obj = __PACKAGE__->new( algorithm => $algorithm, salt => $salt );
    $obj->add($cleardata);

    return $obj->generate eq $hasheddata;
}

=back

=head1 FUNCTIONS

I<none yet.>

=cut

sub make_scheme {

    my $scheme = shift;
    $scheme = "$1$2" if $scheme =~ m!(\w+)\-(\d+)!;

    return uc("S$scheme");
}

sub make_algorithm {

    my $algorithm = shift;
    if ( $algorithm =~ m!^{S(.*)}$! ) {
        $algorithm = $1;
        $algorithm = "$1-$2" if $algorithm =~ m!(\w+)(\d+)!;
    }

    return $algorithm;
}

sub get_pass_scheme {
    $_[0] =~ m/{([^}]*)/;
    return $1;
}

sub get_pass_hash {
    $_[0] =~ m/}([^\s]*)/;
    return $1;
}

sub generate_hex_salt {

    my @keychars = (
        "0", "1", "2", "3", "4", "5", "6", "7",
        "8", "9", "a", "b", "c", "d", "e", "f"
    );
    my $length = 8;

    my $salt = '';
    my $max  = scalar @keychars;
    for my $i ( 0 .. $length - 1 ) {
        my $skip = $i == 0 ? 1 : 0;    # don't let the first be 0
        $salt .= $keychars[ $skip + int( rand( $max - $skip ) ) ];
    }

    return $salt;
}

sub extract_salt {
    my $binhash = &MIME::Base64::decode_base64( $_[0] );
    my $binsalt = substr( $binhash, length($binhash) - 4 );

    return join( '', unpack( 'H*', $binsalt ) );
}

=head1 SEE ALSO

L<Digest>, L<MIME::Base64>

=head1 AUTHOR

Sascha Kiefer, L<esskar@cpan.org>

=head1 ACKNOWLEDGMENTS

The author is particularly grateful to Andres Andreu for his article: Salted
hashes demystified - A Primer (L<http://www.securitydocs.com/library/3439>)

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2005 Sascha Kiefer

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

1;
