#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use FindBin '$Bin';
use Data::Dumper;
use YAML::PP;
use Test::Deep;
use File::Spec;

my @include_paths = ($Bin, "data", "include");

my $yp = YAML::PP->new;
my $schema = $yp->schema;
$schema->add_resolver(
    tag => '!include',
    match => [ all => sub { include($schema, @_) } ],
    implicit => 0,
);

subtest include => sub {

    my $yaml = <<'EOM';
---
- !include include1.yaml
- !include include2.yaml
- item3
EOM
    my ($data) = $yp->load_string($yaml);

    my $expected = [
        'include1',
        [
            'include2',
            'include3',
        ],
        'item3',
    ];

    is_deeply($data, $expected, "!include");
};

subtest invalid_include => sub {
    my $yaml = <<'EOM';
---
- !include ../../../../../../../../../../../etc/passwd
EOM
    my ($data) = eval {
        $yp->load_string($yaml)
    };
    my $error = $@;
    cmp_ok($error, '=~', "Could not open", "Filter out ..");

};


sub include {
    my ($schema, $constructor, $event) = @_;
    my $filename = $event->{value};
    # We need a new object because we are still in the parsing and
    # constructing process
    # But we can resuse the $schema object
    my $yp = YAML::PP->new( schema => $schema );

    my @paths = File::Spec->splitdir($filename);
    @paths = File::Spec->no_upwards(@paths);
    my $path = File::Spec->catfile(
        @include_paths, @paths
    );
    my ($data) = $yp->load_file($path);
    return $data;
}

done_testing;
