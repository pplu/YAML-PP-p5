use strict;
use warnings;
package YAML::PP::Schema::Include;

our $VERSION = '0.000'; # VERSION

sub new {
    my ($class, %args) = @_;

    my $paths = delete $args{paths};
    my $pp_args = delete $args{pp_args} || {};
    unless (ref $paths eq 'ARRAY') {
        $paths = [$paths];
    }
    my $self = bless {
        paths => $paths,
        pp_args => $pp_args,
    }, $class;
    return $self;
}

sub paths { $_[0]->{paths} }
sub pp_args { $_[0]->{pp_args} }

sub register {
    my ($self, %args) = @_;
    my $schema = $args{schema};

    $schema->add_resolver(
        tag => '!include',
        match => [ all => sub { $self->include($schema, @_) } ],
        implicit => 0,
    );
}

sub include {
    my ($self, $schema, $constructor, $event) = @_;
    my $paths = $self->paths;
    my $pp_args = $self->pp_args;
    my $filename = $event->{value};
    # We need a new object because we are still in the parsing and
    # constructing process
    # But we can reuse the $schema object
    my $yp = YAML::PP->new( schema => $schema, %$pp_args );

    my @paths = File::Spec->splitdir($filename);
    @paths = File::Spec->no_upwards(@paths);
    my $fullpath;
    for my $candidate (@$paths) {
        my $test = File::Spec->catfile( $candidate, @paths );
        if (-e $test) {
            $fullpath = $test;
            last;
        }
    }
    die "File '$filename' not found" unless defined $fullpath;
    my ($data) = $yp->load_file($fullpath);
    return $data;
}

1;

__END__

=pod

=encoding utf-8

=head1 NAME

YAML::PP::Schema::Include - Include YAML files

=head1 SYNOPSIS

    my $include_paths = ["/path/to/include/yaml/1", "/path/to/include/yaml/2"];
    my %pp_args = (
        boolean => 'JSON::PP',
        cyclic_refs => 'fatal',
    );
    my $include = YAML::PP::Schema::Include->new(
        paths => $include_paths,
        pp_args => \%pp_args,
    );
    my $yp = YAML::PP->new( schema => ['JSON', $include], %pp_args );

    # file1.yaml
    # ---
    # a: b

    my $yaml = <<'EOM';
    - included: !include file1.yaml
    EOM
    my ($data) = $yp->load_string($yaml);

    # The result will be:
    $data = {
        included => { a => 'b' }
    };

=head1 DESCRIPTION

This plugin allows you to split a large YAML file into smaller ones.

You must specify the paths where to search for files to include. It iterates
through the paths and returns the first filename that exists.

If the included file contains more than one document, only the first one
will be included.

I will probably add a possibility to return all documents as an arrayref.

The included YAML file will be loaded by creating a new L<YAML::PP> object
with the schema from the existing object. This way you can recursively include
files.

You can even reuse the same include via an alias:

    ---
    invoice:
        shipping address: &address !include address.yaml
        billing address: *address

=cut
