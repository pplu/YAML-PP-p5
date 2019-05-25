#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use FindBin '$Bin';
use Data::Dumper;
use YAML::PP;
use YAML::PP::Schema::Include;
use Test::Deep;
use File::Spec;

my $include_path = "$Bin/data/include";

my $yp = YAML::PP->new;
my $schema = $yp->schema;
$schema->add_resolver(
    tag => '!include',
    match => [ all => sub { include($schema, @_) } ],
    implicit => 0,
);
my $valid_yaml = <<'EOM';
---
- !include include1.yaml
- !include include2.yaml
- item3
EOM

my $invalid_yaml = <<'EOM';
---
- !include ../../../../../../../../../../../etc/passwd
EOM

my $expected = [
    'include1',
    [
        'include2',
        'include3',
    ],
    'item3',
];

subtest include => sub {
    my ($data) = $yp->load_string($valid_yaml);
    is_deeply($data, $expected, "!include");
};

subtest invalid_include => sub {
    my ($data) = eval {
        $yp->load_string($invalid_yaml)
    };
    my $error = $@;
    cmp_ok($error, '=~', "not found", "Filter out ..");

};


sub include {
    my ($schema, $constructor, $event) = @_;
    my $filename = $event->{value};
    # We need a new object because we are still in the parsing and
    # constructing process
    # But we can reuse the $schema object
    my $yp = YAML::PP->new( schema => $schema );

    my @paths = File::Spec->splitdir($filename);
    @paths = File::Spec->no_upwards(@paths);
    my $path = File::Spec->catfile(
        $include_path, @paths
    );
    die "File '$filename' not found" unless -e $path;
    my ($data) = $yp->load_file($path);
    return $data;
}

subtest schema_include => sub {

    my $include = YAML::PP::Schema::Include->new( paths => $include_path );
    my $yp = YAML::PP->new( schema => ['JSON', $include] );

    my ($data) = $yp->load_string($valid_yaml);
    is_deeply($data, $expected, "!include");
};

subtest invalid_schema_include => sub {
    my $include = YAML::PP::Schema::Include->new(
        paths => $include_path,
        pp_args => {
            boolean => 'perl',
        },
    );
    my $yp = YAML::PP->new( schema => ['JSON', $include] );
    my ($data) = eval {
        $yp->load_string($invalid_yaml)
    };
    my $error = $@;
    cmp_ok($error, '=~', "not found", "Filter out ..");

};
done_testing;
