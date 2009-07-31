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
# Portions created by Vyatta are Copyright (C) 2009 Vyatta, Inc.
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
    my ($set_name, $member) = @_;
    
    die "Error: undefined member" if ! defined $member; 
    my $group = new Vyatta::IpTables::IpSet($set_name);
    return $group->add_member($member);
}

sub ipset_delete_member {
    my ($set_name, $member) = @_;

    die "Error: undefined member" if ! defined $member; 
    my $group = new Vyatta::IpTables::IpSet($set_name);
    if ($group->exists($set_name) && $group->check_member($member)) {
	return $group->delete_member($member);
    }
    return;
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

sub ipset_show_sets {
    my @lines = `ipset -L -n`;
    foreach my $line (@lines) {
	if ($line =~ /^Name:\s+(\S+)$/ ) {
	    ipset_show_members($1);
	    print "\n";
	}
    }
    return;
}

#
# main
#
my ($action, $set_name, $set_type, $member);

GetOptions("action=s"   => \$action,
           "set-name=s" => \$set_name,
           "set-type=s" => \$set_type,
           "member=s"   => \$member,
);

die "undefined action" if ! defined $action;

my $rc;
$rc = ipset_create($set_name, $set_type) if $action eq 'create-set';

$rc = ipset_delete($set_name) if $action eq 'delete-set';

$rc = ipset_check_member($set_name, $set_type, $member) 
    if $action eq 'check-member';

$rc = ipset_add_member($set_name, $member) if $action eq 'add-member';

$rc = ipset_delete_member($set_name, $member) if $action eq 'delete-member';

$rc = ipset_check_set_type($set_name, $set_type) if $action eq 'check-set-type';

$rc = ipset_show_members($set_name) if $action eq 'show-set-members';

$rc = ipset_show_sets() if $action eq 'show-sets';

if (defined $rc) {
    print $rc;
    exit 1;
}
exit 0;

# end of file
