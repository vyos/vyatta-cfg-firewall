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
    _name   => undef,
    _type   => undef,  # vyatta group type, not ipset type
    _exists => undef,
    _debug  => undef,
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

    return 1 if   defined $self->{_exists};
    return 0 if ! defined $self->{_name};
    my $func = (caller(0))[3];
    my $cmd = "ipset -L $self->{_name}";
    my $rc = system("$cmd > /dev/null &>2");
    system("$logger [$func] [$cmd] = [$rc]") if defined $self->{_debug};
    $self->{_exists} = 1 if $rc eq 0;
    $self->get_type() if ! defined $self->{_type};
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
    my @lines = `ipset -L $self->{_name} -n -s`;
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

sub check_member_address {
    my $member = shift;

    if (!Vyatta::TypeChecker::validateType('ipv4', $member, 1)) {
	return "Error: [$member] isn't valid IPv4 address\n";
    }
    if ($member eq '0.0.0.0') {
	return "Error: zero IP address not valid in address-group\n";
    }
    return;
}

sub check_member {
    my ($self, $member) = @_;

    return "Error: undefined group name" if ! defined $self->{_name};
    return "Error: undefined group type" if ! defined $self->{_type};

    # We can't call $self->member_exists() here since this is a
    # syntax check and the group may not have been created yet
    # if there hasn't been a commit yet on this group.  Move the
    # exists check to $self->add_member().

    if ($self->{_type} eq 'address') {
	if ($member =~ /^([\d\.]+)-([\d\.]+)$/) {
	    foreach my $address ($1, $2) {
		my $rc = check_member_address($address);
		return $rc if defined $rc;
	    }
	} else {
	    my $rc = check_member_address($member);
	    return $rc if defined $rc;
	}
    } elsif ($self->{_type} eq 'network') {
	if (!Vyatta::TypeChecker::validateType('ipv4net', $member, 1)) {
	    return "Error: [$member] isn't a valid IPv4 network\n";
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
	if ($member =~ /^(\d+)-(\d+)$/) {
	    my ($success, $err) = Vyatta::Misc::isValidPortRange($member, '-');
	    if (!defined $success) {
		return "Error: [$member] isn't a valid port range\n";
	    }
	} elsif ($member =~ /^\d/) {
	    my ($success, $err) = Vyatta::Misc::isValidPortNumber($member);
	    if (!defined $success) {
		return "Error: [$member] isn't a valid port number\n";
	    }
	} else {
	    my ($success, $err) = Vyatta::Misc::isValidPortName($member);
	    if (!defined $success) {
		return "Error: [$member] isn't a valid port name\n";
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

sub add_member_range {
    my ($self, $start, $stop) = @_;    
    
    if ($self->{_type} eq 'port') {
	foreach my $member ($start .. $stop) {
	    my $rc = $self->add_member($member);
	    return $rc if defined $rc;
	}
    } elsif ($self->{_type} eq 'address') {
	# $start_ip++ won't work if it doesn't know the 
	# prefix, so we'll make a big range.
	my $start_ip = new NetAddr::IP("$start/16");
	my $stop_ip  = new NetAddr::IP($stop);
	for (; $start_ip <= $stop_ip; $start_ip++) {
	    my $rc = $self->add_member($start_ip->addr());
	    return $rc if defined $rc;
	}
    }
    return;
}

sub add_member {
    my ($self, $member) = @_;

    return "Error: undefined group name" if ! defined $self->{_name};
    return "Error: group [$self->{_name}] doesn't exists\n" if !$self->exists();

    if ($member =~ /^([^-]+)-([^-]+)$/) {
	return $self->add_member_range($1, $2);
    }

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

sub delete_member_range {
    my ($self, $start, $stop) = @_;    
    
    if ($self->{_type} eq 'port') {
	foreach my $member ($start .. $stop) {
	    my $rc = $self->delete_member($member);
	    return $rc if defined $rc;
	}
    } elsif ($self->{_type} eq 'address') {
	my $start_ip = new NetAddr::IP("$start/16");
	my $stop_ip  = new NetAddr::IP($stop);
	for (; $start_ip <= $stop_ip; $start_ip++) {
	    my $rc = $self->delete_member($start_ip->addr());
	    return $rc if defined $rc;
	}
    }
    return;
}

sub delete_member {
    my ($self, $member) = @_;

    return "Error: undefined group name" if ! defined $self->{_name};
    return "Error: group [$self->{_name}] doesn't exists\n" if !$self->exists();

    if ($member =~ /^([^-]+)-([^-]+)$/) {
	return $self->delete_member_range($1, $2);
    }

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

sub get_description {
    my ($self) = @_;

    return if ! $self->exists();
    my $config = new Vyatta::Config;
    my $group_type = "$self->{_type}-group";
    $config->setLevel("firewall group $group_type $self->{_name}");    
    return $config->returnOrigValue('description');
}

sub get_firewall_references {
    my ($self) = @_;
    
    my @fw_refs = ();
    return @fw_refs if ! $self->exists();
    my $config = new Vyatta::Config;
    foreach my $tree ('name', 'modify') {
	my $path = "firewall $tree ";
	$config->setLevel($path);
	my @names = $config->listOrigNodes();
	foreach my $name (@names) {
	    my $name_path = "$path $name rule ";
	    $config->setLevel($name_path);
	    my @rules = $config->listOrigNodes();
	    foreach my $rule (@rules) {
		foreach my $dir ('source', 'destination') {
		    my $rule_path = "$name_path $rule $dir group";
		    $config->setLevel($rule_path);
		    my $group_type = "$self->{_type}-group";
		    my $value =  $config->returnOrigValue($group_type);
		    if (defined $value and $self->{_name} eq $value) {
			push @fw_refs, "$name-$rule-$dir";
		    }
		} # foreach $dir
	    } # foreach $rule
	} # foreach $name
    } # foreach $tree
    return @fw_refs;
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
