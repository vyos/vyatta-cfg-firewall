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
# Portions created by Vyatta are Copyright (C) 2009-2010 Vyatta, Inc.
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
    _family => undef,
    _exists => undef,
    _negate => undef,
    _debug  => undef,
);

our %grouptype_hash = (
    'address' => 'hash:ip',
    'network' => 'hash:net',
    'port'    => 'bitmap:port'
);

my $logger = 'logger -t IpSet.pm -p local0.warn --';

# Currently we restrict an address range to a /24 even
# though ipset would support a /16.  The main reason is
# due to the long time it takes to make that many calls
# to add each individual member to the set.
my $addr_range_mask = 24;
my $lockfile = "/opt/vyatta/config/.lock";

# remove lock file to avoid commit blockade on interrupt
# like CTRL+C.
sub INT_handler {
    my $rc = system("sudo rm -f $lockfile >>/dev/null");
    exit(0);
}

$SIG{'INT'} = 'INT_handler';

sub new {
    my ($that, $name, $type, $family) = @_;

    my $class = ref($that) || $that;
    my $self = {%fields,};
    if ($name =~ m/^!/) {
        $self->{_negate} = 1;
        $name =~ s/^!(.*)$/$1/;
    }
    $self->{_name} = $name;
    $self->{_type} = $type;
    $self->{_family} = $family;

    bless $self, $class;
    return $self;
}

sub debug {
    my ($self, $onoff) = @_;

    $self->{_debug} = undef;
    $self->{_debug} = 1 if $onoff eq "on";
}

sub run_cmd {
    my ($self, $cmd) = @_;

    my $rc = system("sudo $cmd");
    if (defined $self->{_debug}) {
        my $func = (caller(1))[3];
        system("$logger [$func] [$cmd] = [$rc]");
    }
    return $rc;
}

sub exists {
    my ($self) = @_;

    return 1 if   defined $self->{_exists};
    return 0 if !defined $self->{_name};
    my $cmd = "ipset -L $self->{_name} > /dev/null 2>&1";
    my $rc = $self->run_cmd($cmd);
    if ($rc eq 0) {
        $self->{_exists} = 1;
        $self->get_type() if !defined $self->{_type};
    }
    return $rc ? 0 : 1;
}

sub get_type {
    my ($self) = @_;

    return $self->{_type} if defined $self->{_type};
    return if !$self->exists();
    my @lines = `ipset -L $self->{_name}`;
    my $type;
    foreach my $line (@lines) {
        if ($line =~ /^Type:\s+([\w:]+)$/) {
            $type = $1;
            last;
        }
    }
    return if !defined $type;
    foreach my $vtype (keys(%grouptype_hash)) {
        if ($grouptype_hash{$vtype} eq $type) {
            $self->{_type} = $vtype;
            last;
        }
    }
    return $self->{_type};
}

sub get_family {
    my ($self) = @_;
    return $self->{_family} if defined $self->{_family};
    return if !$self->exists();
    my @lines = `ipset -L $self->{_name}`;
    my $family;
    foreach my $line (@lines) {
        if ($line =~ /^Header: family (\w+) hashsize/) {
            $family = $1;
            $self->{_family} = $family;
            last;
        } elsif ($line =~ /^Type: bitmap:port$/){
            $self->{_family} = "inet";
            last;
        }
    }
    return $self->{_family};
}

sub alphanum_split {
    my ($str) = @_;
    my @list = split m/(?=(?<=\D)\d|(?<=\d)\D)/, $str;
    return @list;
}

sub natural_order {
    my ($a, $b) = @_;
    my @a = alphanum_split($a);
    my @b = alphanum_split($b);

    while (@a && @b) {
        my $a_seg = shift @a;
        my $b_seg = shift @b;
        my $val;
        if (($a_seg =~ /\d/) && ($b_seg =~ /\d/)) {
            $val = $a_seg <=> $b_seg;
        } else {
            $val = $a_seg cmp $b_seg;
        }
        if ($val != 0) {
            return $val;
        }
    }
    return @a <=> @b;
}

sub get_members {
    my ($self) = @_;

    my @members = ();
    return @members if !$self->exists();

    my @lines = `ipset -L $self->{_name} -s`;
    foreach my $line (@lines) {
        push @members, $line if $line =~ /^\d/;
    }
    if ($self->{_type} ne 'port') {
        @members = sort {natural_order($a,$b)} @members;
    }
    return @members;
}

sub create {
    my ($self) = @_;

    return "Error: undefined group name" if !defined $self->{_name};
    return "Error: undefined group type" if !defined $self->{_type};
    return if $self->exists(); # treat as nop if already exists

    my $ipset_param = $grouptype_hash{$self->{_type}};
    return "Error: invalid group type\n" if !defined $ipset_param;

    my $cmd = "ipset -N $self->{_name} $ipset_param family $self->{_family}";

    if ($self->{_type} eq 'port') {
        $ipset_param .= ' --from 1 --to 65535';
        $cmd = "ipset -N $self->{_name} $ipset_param";
    }

    my $rc = $self->run_cmd($cmd);
    return "Error: call to ipset failed [$rc]" if $rc;
    return; # undef
}

sub references {
    my ($self) = @_;

    return 0 if !$self->exists();
    my @lines = `ipset -L $self->{_name}`;
    foreach my $line (@lines) {
        if ($line =~ /^References:\s+(\d+)$/) {
            return $1;
        }
    }
    return 0;
}

sub flush {
    my ($self) = @_;
    my $cmd = "ipset flush $self->{_name}";
    my $rc = $self->run_cmd($cmd);
    return "Error: call to ipset failed [$rc]" if $rc;
    return;
}

sub rebuild_ipset() {
    my ($self) = @_;
    my $name = $self->{_name};
    my $type = $self->{_type};
    my $config = new Vyatta::Config;

    my @members = $config->returnOrigValues("firewall group $type-group $name $type");

    # go through the firewall group config with this name,
    my $member;
    foreach $member (@members) {
        $self->add_member($member, $name);
    }
}

sub reset_ipset_named {
    my ($self) = @_;
    my $name = $self->{_name};

    # flush the ipset group first, then re-build the group from configuration
    $self->flush();

    $self->rebuild_ipset();
}

sub reset_ipset_all {
    my $config = new Vyatta::Config;
    my @pgroups = $config->listOrigNodes("firewall group port-group");
    my @adgroups = $config->listOrigNodes("firewall group address-group");
    my @nwgroups = $config->listOrigNodes("firewall group network-group");
    my $group;

    foreach $group (@pgroups) {
        my $grp = new Vyatta::IpTables::IpSet($group, "port");
        $grp->reset_ipset_named();
    }
    foreach $group (@adgroups) {
        my $grp = new Vyatta::IpTables::IpSet($group, "address");
        $grp->reset_ipset_named();
    }
    foreach $group (@nwgroups) {
        my $grp = new Vyatta::IpTables::IpSet($group, "network");
        $grp->reset_ipset_named();
    }
}

sub reset_ipset {

    # main function to do the reset operation
    my ($self) = @_;
    my $name = $self->{_name};

    my $lockcmd = "touch $lockfile";
    my $unlockcmd = "rm -f $lockfile";
    $self->run_cmd($lockcmd);

    # reset one rule or all?
    if ($name eq 'all') {
        $self->reset_ipset_all();
    } else {
        $self->reset_ipset_named();
    }
    my $rc = $self->run_cmd($unlockcmd);
    return "Error: call to ipset failed [$rc]" if $rc;
    return; # undef
}

sub delete {
    my ($self) = @_;

    return "Error: undefined group name" if !defined $self->{_name};
    return "Error: group [$self->{_name}] doesn't exists\n" if !$self->exists();

    my $refs = $self->references();
    if ($refs > 0) {

        # still in use
        if (scalar($self->get_firewall_references(1)) > 0) {

            # still referenced by config
            return "Error: group [$self->{_name}] still in use.\n";
        }

        # not referenced by config => simultaneous deletes. just do flush.
        return $self->flush();
    }

    my $cmd = "ipset -X $self->{_name}";
    my $rc = $self->run_cmd($cmd);
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

    return "Error: undefined group name" if !defined $self->{_name};
    return "Error: undefined group type" if !defined $self->{_type};

    # We can't call $self->member_exists() here since this is a
    # syntax check and the group may not have been created yet
    # if there hasn't been a commit yet on this group.  Move the
    # exists check to $self->add_member().

    if ($self->{_type} eq 'address') {
        if ($member =~ /^([^-]+)-([^-]+)$/) {
            foreach my $address ($1, $2) {
                my $rc = check_member_address($address);
                return $rc if defined $rc;
            }
            my $start_ip = new NetAddr::IP($1);
            my $stop_ip  = new NetAddr::IP($2);
            if ($stop_ip <= $start_ip) {
                return "Error: $1 must be less than $2\n";
            }
            my $start_net = new NetAddr::IP("$1/$addr_range_mask");
            if (!$start_net->contains($stop_ip)) {
                return "Error: address range must be within /$addr_range_mask\n";
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
            return "Error: 0.0.0.0/0 invalid in network-group\n"
                if (($net eq '0.0.0.0') and ($mask == 0));
            return "Error: invalid mask [$mask] - must be between 1-31\n"
                if (($mask < 1) or ($mask > 31));
        } else {
            return "Error: Invalid network group [$member]\n";
        }
    } elsif ($self->{_type} eq 'port') {
        my ($success, $err) = (undef, "invalid port [$member]");
        if ($member =~ /^(\d+)-(\d+)$/) {
            ($success, $err) = Vyatta::Misc::isValidPortRange($member, '-');
        } elsif ($member =~ /^\d/) {
            ($success, $err) = Vyatta::Misc::isValidPortNumber($member);
        } else {
            ($success, $err) = Vyatta::Misc::isValidPortName($member);
        }
        return "Error: $err\n" if defined $err;
    } else {
        return "Error: invalid set type [$self->{_type}]";
    }
    return; #undef
}

sub member_exists {
    my ($self, $member) = @_;

    # check if a member is a port range and roll through all members it is
    if ($member =~ /([\d]+)-([\d]+)/) {
        foreach my $port ($1..$2) {
            # test port with ipset
            my $cmd = "ipset -T $self->{_name} $port -q";
            my $rc = $self->run_cmd($cmd);
            # return true if port was found
            return 1 if !$rc;
        }
        # return false if ports was not found in set
        return 0;
    } else {
        my $cmd = "ipset -T $self->{_name} $member -q";
        my $rc = $self->run_cmd($cmd);
        return $rc ? 0 : 1;
    }
}


sub add_member {
    my ($self, $member, $alias, $hyphenated_port) = @_;

    return "Error: undefined group name" if !defined $self->{_name};
    return "Error: group [$self->{_name}] doesn't exists\n" if !$self->exists();

    if ($self->member_exists($member)) {
        my $set_name = $alias;
        $set_name = $self->{_name} if !defined $set_name;
        return "Error: member [$member] already exists in [$set_name]\n";
    }
    my $cmd = "ipset -A $self->{_name} $member";
    my $rc = $self->run_cmd($cmd);
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
        my $start_ip = new NetAddr::IP("$start/$addr_range_mask");
        my $stop_ip  = new NetAddr::IP("$stop/$addr_range_mask");
        for (; $start_ip <= $stop_ip; $start_ip++) {
            my $rc = $self->delete_member($start_ip->addr());
            return $rc if defined $rc;
            last if $start_ip->cidr() eq $start_ip->broadcast();
        }
    }
    return;
}

sub delete_member {
    my ($self, $member, $hyphenated_port) = @_;

    return "Error: undefined group name" if !defined $self->{_name};
    return "Error: group [$self->{_name}] doesn't exists\n" if !$self->exists();

    # service name or port name may contain a hyphen, which needs to be escaped
    # using square brackets in ipset, to avoid confusion with port ranges
    if (($member =~ /^([^-]+)-([^-]+)$/) and ((defined($hyphenated_port)) and ($hyphenated_port eq 'false'))) {
        return $self->delete_member_range($1, $2);
    }

    if (!$self->member_exists($member)) {
        return "Error: member [$member] doesn't exists in [$self->{_name}]\n";
    }
    my $cmd = "ipset -D $self->{_name} $member";
    my $rc = $self->run_cmd($cmd);
    return "Error: call to ipset failed [$rc]" if $rc;
    return; # undef
}

sub get_description {
    my ($self) = @_;

    return if !$self->exists();
    my $config = new Vyatta::Config;
    my $group_type = "$self->{_type}-group";
    $config->setLevel("firewall group $group_type $self->{_name}");
    return $config->returnOrigValue('description');
}

sub get_firewall_references {
    my ($self, $working) = @_;
    my ($lfunc, $vfunc) = qw(listOrigNodes returnOrigValue);
    if ($working) {
        ($lfunc, $vfunc) = qw(listNodes returnValue);
    }
    my @fw_refs = ();
    return @fw_refs if !$self->exists();
    my $config = new Vyatta::Config;
    foreach my $tree ('name', 'ipv6-name', 'modify') {
        my $path = "firewall $tree ";
        $config->setLevel($path);
        my @names = $config->$lfunc();
        foreach my $name (@names) {
            my $name_path = "$path $name rule ";
            $config->setLevel($name_path);
            my @rules = $config->$lfunc();
            foreach my $rule (@rules) {
                foreach my $dir ('source', 'destination') {
                    my $rule_path = "$name_path $rule $dir group";
                    $config->setLevel($rule_path);
                    my $group_type = "$self->{_type}-group";
                    my $value =  $config->$vfunc($group_type);
                    $value =~ s/^!(.*)$/$1/ if defined $value;
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

    if (!$self->exists()) {
        my $name = $self->{_name};
        $name = 'undefined' if !defined $name;
        return (undef, "Undefined group [$name]");
    }

    my $srcdst;
    my $grp = $self->{_name};
    $srcdst = 'src' if $direction eq 'source';
    $srcdst = 'dst' if $direction eq 'destination';

    return (undef, "Invalid direction [$direction]") if !defined $srcdst;
    my $opt = '';
    $opt = '!' if $self->{_negate};
    return (" -m set $opt --match-set $grp $srcdst ",);
}

1;
