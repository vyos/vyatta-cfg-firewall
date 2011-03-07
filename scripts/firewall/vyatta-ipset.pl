#!/usr/bin/perl
#
# Module: vyatta-ipset.pl
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
# Description: Script to configure ipset to support firewall groups
# 
# **** End License ****
#

use Getopt::Long;
use POSIX;

use lib "/opt/vyatta/share/perl5";
use Vyatta::Config;
use Vyatta::TypeChecker;
use Vyatta::Misc;
use Vyatta::IpTables::IpSet;

use warnings;
use strict;


sub ipset_create {
    my ($set_name, $set_type) = @_;

    my $group = new Vyatta::IpTables::IpSet($set_name, $set_type);

    return $group->create();
}

sub ipset_delete {
    my $set_name = shift;

    my $group = new Vyatta::IpTables::IpSet($set_name);
    return $group->delete();
}

sub ipset_check_member {
    my ($set_name, $set_type, $member) = @_;

    die "undefined type or member" if ! defined $set_type or ! defined $member;

    my $group = new Vyatta::IpTables::IpSet($set_name, $set_type);
    return $group->check_member($member);
}

sub ipset_add_member {
    my ($set_name, $member, $alias) = @_;
    
    die "Error: undefined member" if ! defined $member; 
    my $group = new Vyatta::IpTables::IpSet($set_name);
    return $group->add_member($member, $alias);
}

sub ipset_delete_member {
    my ($set_name, $member) = @_;

    die "Error: undefined member" if ! defined $member; 
    my $group = new Vyatta::IpTables::IpSet($set_name);
    return $group->delete_member($member);
}

sub ipset_check_set_type {
   my ($set_name, $set_type) = @_;

   die "Error: undefined set_name\n" if ! defined $set_name; 
   die "Error: undefined set_type\n" if ! defined $set_type; 

   my $group = new Vyatta::IpTables::IpSet($set_name);
   return "Group [$set_name] has not been defined\n" if ! $group->exists();
   my $type = $group->get_type();
   $type = 'undefined' if ! defined $type;
   if ($type ne $set_type) {
       return "Error: group [$set_name] is of type [$type] not [$set_type]\n";
   }
   return;
}

sub ipset_show_members {
    my ($set_name) = @_;

    die "Error: undefined set_name\n" if ! defined $set_name; 
    my $group = new Vyatta::IpTables::IpSet($set_name);
    return "Group [$set_name] has not been defined\n" if ! $group->exists();
    my $type    = $group->get_type();
    my @members = $group->get_members();
    my $desc    = $group->get_description();
    my @fw_refs = $group->get_firewall_references();
    push @fw_refs, 'none' if scalar(@fw_refs) == 0;

    my $padding = ' ' x 13;
    print "Name       : $set_name\n";
    print "Type       : $type\n";
    print "Description: $desc\n" if defined $desc;
    print "References : ", join(', ', @fw_refs), "\n";
    print "Members    :\n";
    print $padding, join($padding, @members);
    return;
}

sub ipset_is_set_empty {
    my ($set_name) = @_;
    
    die "Error: undefined set_name\n" if ! defined $set_name; 
    my $group = new Vyatta::IpTables::IpSet($set_name);
    return "Group [$set_name] has not been defined\n" if ! $group->exists();
    my @members = $group->get_members();
    exit 0 if scalar(@members) > 0;
    exit 1;
}

sub ipset_show_sets {
    my @lines = `ipset -L`;
    foreach my $line (@lines) {
	if ($line =~ /^Name:\s+(\S+)$/ ) {
	    ipset_show_members($1);
	    print "\n";
	}
    }
    return;
}

sub ipset_copy_set {
    my ($set_name, $set_type, $set_copy) = @_;

    die "Error: undefined set_name\n" if ! defined $set_name; 
    die "Error: undefined set_type\n" if ! defined $set_type; 
    die "Error: undefined set_copy\n" if ! defined $set_copy; 

    my $group = new Vyatta::IpTables::IpSet($set_name);
    my $copy  = new Vyatta::IpTables::IpSet($set_copy, $set_type);

    if ($copy->exists()) {
        return "Error: copy already exists [$set_copy]\n";
    }

    if ($group->exists()) {
        my $type = $group->get_type();
        if ($type ne $set_type) {
            return "Error: type mismatch [$type] [$set_type]\n";
        }
        # copy members to new group
        my $tmpfile = "/tmp/set.$$";
        system("ipset -S $set_name > $tmpfile");
        system("sed -i \'s/ $set_name / $set_copy /g\' $tmpfile");
        system("ipset -R < $tmpfile");
        unlink $tmpfile;
        my $copy  = new Vyatta::IpTables::IpSet($set_copy, $set_type);
        return if $copy->exists();
        return "Error: problem copying group\n";
    } else {
        my $rc = $group->create();
        return $rc;
    }
}

sub ipset_is_group_deleted {
    my ($set_name, $set_type) = @_;

    die "Error: undefined set_name\n" if ! defined $set_name; 
    die "Error: undefined set_type\n" if ! defined $set_type; 

    my $config = new Vyatta::Config;
    $config->setLevel("firewall group $set_type-group");
    my %nodes = $config->listNodeStatus();

    if ($nodes{$set_name} eq 'deleted') {
        exit 0;
    } else {
        exit 1;
    }
}

sub ipset_is_group_used {
    my ($set_name, $set_type) = @_;

    die "Error: undefined set_name\n" if ! defined $set_name; 
    die "Error: undefined set_type\n" if ! defined $set_type; 

    my $group = new Vyatta::IpTables::IpSet($set_name);
    my $refs = $group->references();
    exit 0 if $refs > 0;
    exit 1;
}


#
# main
#
my ($action, $set_name, $set_type, $member, $set_copy, $alias);

GetOptions("action=s"   => \$action,
           "set-name=s" => \$set_name,
           "set-type=s" => \$set_type,
           "member=s"   => \$member,
           "alias=s"    => \$alias,
           "set-copy=s" => \$set_copy,
);

die "undefined action" if ! defined $action;

my $rc;
$rc = ipset_create($set_name, $set_type) if $action eq 'create-set';

$rc = ipset_delete($set_name) if $action eq 'delete-set';

$rc = ipset_check_member($set_name, $set_type, $member) 
    if $action eq 'check-member';

$rc = ipset_add_member($set_name, $member, $alias) if $action eq 'add-member';

$rc = ipset_delete_member($set_name, $member) if $action eq 'delete-member';

$rc = ipset_check_set_type($set_name, $set_type) if $action eq 'check-set-type';

$rc = ipset_show_members($set_name) if $action eq 'show-set-members';

$rc = ipset_show_sets() if $action eq 'show-sets';

$rc = ipset_is_set_empty($set_name) if $action eq 'is-set-empty'; 

$rc = ipset_copy_set($set_name, $set_type, $set_copy) if $action eq 'copy-set';

$rc = ipset_is_group_deleted($set_name, $set_type) 
    if $action eq 'is-group-deleted';

$rc = ipset_is_group_used($set_name, $set_type) if $action eq 'is-group-used';

if (defined $rc) {
    print $rc;
    exit 1;
}
exit 0;

# end of file
