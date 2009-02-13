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
    _type  => undef,  # vyatta group type, not ipset type
    _debug => undef,
);

my %grouptype_hash = (
    'address' => 'iphash',
    'network' => 'nethash',
    'port'    => 'portmap'
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
    my $rc = system("$cmd > /dev/null &>2");
    system("$logger [$func] [$cmd] = [$rc]") if defined $self->{_debug};
    return $rc ? 0 : 1;
}

sub get_type {
    my ($self) = @_;

    return $self->{_type} if defined $self->{_type};
    return if ! $self->exists();
    my @lines = `ipset -L $self->{_name}`;
    my $type;
    foreach my $line (@lines) {
	if ($line =~ /^Type:\s+(\w+)$/) {
	    $type = $1;
	    last;
	}
    }
    return if ! defined $type;
    foreach my $vtype (keys(%grouptype_hash)) {
	if ($grouptype_hash{$vtype} eq $type) {
	    $self->{_type} = $vtype;
	    last;
	}
    }
    return $self->{_type};
}

sub get_members {
    my ($self) = @_;
    
    my @members = ();
    if (! defined $self->{_type}) {
	return @members if ! $self->exists();
    }
    my @lines = `ipset -L $self->{_name} -n`;
    foreach my $line (@lines) {
	push @members, $line if $line =~ /^\d/;
    }
    return @members;
}

sub create {
    my ($self) = @_;
        
    return "Error: undefined group name" if ! defined $self->{_name};
    return "Error: undefined group type" if ! defined $self->{_type};
    return "Error: group [$self->{_name}] already exists" if $self->exists();
	
    my $ipset_param = $grouptype_hash{$self->{_type}};
    return "Error: invalid group type\n" if ! defined $ipset_param;

    if ($self->{_type} eq 'port') {
	$ipset_param .= ' --from 1 --to 65535';
    } 
    
    my $func = (caller(0))[3];
    my $cmd = "ipset -N $self->{_name} $ipset_param";
    my $rc = system("$cmd");
    system("$logger [$func] [$cmd] = [$rc]") if defined $self->{_debug};
    return "Error: call to ipset failed [$rc]" if $rc;
    return; # undef
}

sub references {
    my ($self) = @_;

    return 0 if ! $self->exists();
    my @lines = `ipset -L $self->{_name}`;
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
    my $rc = system("$cmd");
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
	if ($member eq '0.0.0.0') {
	    return "Error: zero IP address not valid in address-group\n";
	}
    } elsif ($self->{_type} eq 'network') {
	if (!Vyatta::TypeChecker::validateType('ipv4net', $member, 1)) {
	    return "Error: [$member] isn't valid IPv4 network\n";
	}
	if ($member =~ /([\d.]+)\/(\d+)/) {
	    my ($net, $mask) = ($1, $2);
	    return "Error: zero net invalid in network-group\n" 
		if $net eq '0.0.0.0';
	    return "Error: invalid mask [$mask] - must be between 1-31\n"
		if $mask < 1 or $mask > 31;
	} else {
	    return "Error: Invalid network group [$member]\n";
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
    my $rc = system("$cmd");
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
    my $rc = system("$cmd");
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
    my $rc = system("$cmd");
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
    return (" -m set --set $grp $srcdst ", );
}

1;
