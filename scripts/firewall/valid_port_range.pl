#!/usr/bin/env perl

$arg = $ARGV[0];

exit(1) unless $arg =~ /^!?((\d+|\d+-\d+|[a-zA-Z0-9\-]+),)*((\d+|\d+-\d+|[a-zA-Z0-9\-]+))$/;
