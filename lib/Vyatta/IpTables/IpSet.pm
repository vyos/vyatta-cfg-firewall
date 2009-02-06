#!/usr/bin/perl
#
# Module: IpSet.pm
# 
# **** License ****
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
# 
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
# 
# This code was originally developed by Vyatta, Inc.
# Portions created by Vyatta are Copyright (C) 2009 Vyatta, Inc.
# All Rights Reserved.
# 
# Author: Stig Thormodsrud
# Date: January 2009
# Description: vyatta interface to ipset
# 
# **** End License ****
#

package Vyatta::IpTables::IpSet;

use Vyatta::Config;
use Vyatta::TypeChecker;
use Vyatta::Misc;
use NetAddr::IP;

use strict;
use warnings;

my %fields = (
    _name  => undef,
    _type  => undef,
    _debug => undef,
);

my $logger = 'logger -t IpSet.pm -p local0.warn --';

sub new {
    my ($that, $name, $type) = @_;

    my $class = ref ($that) || $that;
    my $self = {
	%fields,
    };
    $self->{_name} = $name;
    $self->{_type} = $type;
    
    bless $self, $class;
    return $self;
}

sub debug {
    my ($self, $onoff) = @_;

    $self->{_debug} = undef;
    $self->{_debug} = 1 if $onoff eq "on";
}

sub exists {
    my ($self) = @_;

    return 0 if ! defined $self->{_name};
    my $func = (caller(0))[3];
    my $cmd = "ipset -L $self->{_name}";
    my $rc = system("sudo $cmd > /dev/null &>2");
    system("$logger [$func] [$cmd] = [$rc]") if defined $self->{_debug};
    return $rc ? 0 : 1;
}

sub get_type {
    my ($self) = @_;

    return if ! $self->exists();
    my @lines = `sudo ipset -L $self->{_name}`;
    foreach my $line (@lines) {
	if ($line =~ /^Type:\s+(\w+)$/) {
	    $self->{_type} = $1;
	    last;
	}
    }
    return if ! defined $self->{_type};
    $self->{_type} = 'address' if $self->{_type} eq 'iphash';
    $self->{_type} = 'network' if $self->{_type} eq 'nethash';
    $self->{_type} = 'port'    if $self->{_type} eq 'portmap';
    return $self->{_type};
}

sub create {
    my ($self) = @_;
        
    return "Error: undefined group name" if ! defined $self->{_name};
    return "Error: undefined group type" if ! defined $self->{_type};
    return "Error: group [$self->{_name}] already exists" if $self->exists();
	
    my $ipset_param;
    if ($self->{_type} eq 'address') {
	$ipset_param = 'iphash';
    } elsif ($self->{_type} eq 'network') {
	$ipset_param = 'nethash';
    } elsif ($self->{_type} eq 'port') {
	$ipset_param = 'portmap --from 1 --to 65535';
    } else {
	return "Error: invalid group type";
    }
    
    my $func = (caller(0))[3];
    my $cmd = "ipset -N $self->{_name} $ipset_param";
    my $rc = system("sudo $cmd");
    system("$logger [$func] [$cmd] = [$rc]") if defined $self->{_debug};
    return "Error: call to ipset failed [$rc]" if $rc;
    return; # undef
}

sub references {
    my ($self) = @_;

    return 0 if ! $self->exists();
    my @lines = `sudo ipset -L $self->{_name}`;
    foreach my $line (@lines) {
	if ($line =~ /^References:\s+(\d+)$/) {
	    return $1;
	}
    }
    return 0;
}

sub delete {
    my ($self) = @_;

    return "Error: undefined group name" if ! defined $self->{_name};
    return "Error: group [$self->{_name}] doesn't exists\n" if !$self->exists();

    my $refs = $self->references();
    return "Error: group [$self->{_name}] still in use.\n" if $refs != 0;

    my $func = (caller(0))[3];
    my $cmd = "ipset -X $self->{_name}";
    my $rc = system("sudo $cmd");
    system("$logger [$func] [$cmd] = [$rc]") if defined $self->{_debug};
    return "Error: call to ipset failed [$rc]" if $rc;
    return; # undef
}

sub check_member {
    my ($self, $member) = @_;

    return "Error: undefined group name" if ! defined $self->{_name};
    return "Error: undefined group type" if ! defined $self->{_type};

    if ($self->{_type} eq 'address') {
	if (!Vyatta::TypeChecker::validateType('ipv4', $member, 1)) {
	    return "Error: [$member] isn't valid IPv4 address\n";
	}
    } elsif ($self->{_type} eq 'network') {
	if (!Vyatta::TypeChecker::validateType('ipv4net', $member, 1)) {
	    return "Error: [$member] isn't valid IPv4 network\n";
	}
    } elsif ($self->{_type} eq 'port') {
	if ($member =~ /^\d/) {
	    my ($success, $err) = Vyatta::Misc::isValidPortNumber($member);
	    if (!defined $success) {
		return "Error: [$member] isn't valid port number\n";
	    }
	} else {
	    my ($success, $err) = Vyatta::Misc::isValidPortName($member);
	    if (!defined $success) {
		return "Error: [$member] isn't valid port name\n";
	    }
	}
    } else {
	return "Error: invalid set type [$self->{_type}]";
    }
    return; #undef 
}

sub member_exists {
    my ($self, $member) = @_;
    
    my $func = (caller(0))[3];
    my $cmd = "ipset -T $self->{_name} $member -q";
    my $rc = system("sudo $cmd");
    system("$logger [$func] [$cmd] = [$rc]") if defined $self->{_debug};
    return $rc ? 0 : 1;    
}

sub add_member {
    my ($self, $member) = @_;

    return "Error: undefined group name" if ! defined $self->{_name};
    return "Error: group [$self->{_name}] doesn't exists\n" if !$self->exists();

    if ($self->member_exists($member)) {
	return "Error: member [$member] already exists in [$self->{_name}]\n";
    }
    my $func = (caller(0))[3];
    my $cmd = "ipset -A $self->{_name} $member";
    my $rc = system("sudo $cmd");
    system("$logger [$func] [$cmd] = [$rc]") if defined $self->{_debug};
    return "Error: call to ipset failed [$rc]" if $rc;
    return; # undef
}

sub delete_member {
    my ($self, $member) = @_;

    return "Error: undefined group name" if ! defined $self->{_name};
    return "Error: group [$self->{_name}] doesn't exists\n" if !$self->exists();

    if (!$self->member_exists($member)) {
	return "Error: member [$member] doesn't exists in [$self->{_name}]\n";
    }
    my $func = (caller(0))[3];
    my $cmd = "ipset -D $self->{_name} $member";
    my $rc = system("sudo $cmd");
    system("$logger [$func] [$cmd] = [$rc]") if defined $self->{_debug};
    return "Error: call to ipset failed [$rc]" if $rc;
    return; # undef
}

sub rule {
    my ($self, $direction) = @_;

    if (! $self->exists()) {
	my $name = $self->{_name};
	$name = 'undefined' if ! defined $name;
	return (undef, "Undefined group [$name]");
    }

    my $srcdst;
    my $grp = $self->{_name};
    $srcdst = 'src' if $direction eq 'source';
    $srcdst = 'dst' if $direction eq 'destination';

    return (undef, "Invalid direction [$direction]") if ! defined $srcdst;
    return ("-m set --set $grp $srcdst ", );
}

1;
