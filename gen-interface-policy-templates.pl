#!/usr/bin/perl
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
# Author: Bob Gilligan (gilligan@vyatta.com)
# Date: March 2009
# Description: Script to automatically generate per-interface firewall
#              templates.
#
# Portions copyright by VyOS maintainers and contributors, 2015.
# 
# **** End License ****
#
use strict;
use warnings;

# Set to 1 to enable debug output.
#
my $debug = 0;

# This hash maps the root of the tree of firewall templates for each interface
# into the variable reference that each of the node.def files in that tree
# will need to use to get the interface name.  The keys of this hash are
# the partial pathname under the config template tree "interfaces/".
#
my %interface_hash = (
    'bonding/node.tag'                               => '$VAR(../../@)',
    'bonding/node.tag/vif/node.tag'                  => '$VAR(../../../@).$VAR(../../@)',
    'bonding/node.tag/vif-s/node.tag'                => '$VAR(../../../@).$VAR(../../@)',
    'bonding/node.tag/vif-s/node.tag/vif-c/node.tag' => '$VAR(../../../../@).$VAR(../../../@).$VAR(../../@)',

    'ethernet/node.tag'                             => '$VAR(../../@)',
    'ethernet/node.tag/pppoe/node.tag'              => 'pppoe$VAR(../../@)',
    'ethernet/node.tag/vif/node.tag'                => '$VAR(../../../@).$VAR(../../@)',
    'ethernet/node.tag/vif/node.tag/pppoe/node.tag' => 'pppoe$VAR(../../@)',
    'ethernet/node.tag/vif-s/node.tag'                => '$VAR(../../../@).$VAR(../../@)',
    'ethernet/node.tag/vif-s/node.tag/vif-c/node.tag'   => '$VAR(../../../../@).$VAR(../../../@).$VAR(../../@)',

    'pseudo-ethernet/node.tag'                           => '$VAR(../../@)',
    'pseudo-ethernet/node.tag/vif/node.tag'              => '$VAR(../../../@).$VAR(../../@)',
    'pseudo-ethernet/node.tag/vif-s/node.tag'              => '$VAR(../../../@).$VAR(../../@)',
    'pseudo-ethernet/node.tag/vif-s/node.tag/vif-c/node.tag' => '$VAR(../../../../@).$VAR(../../../@).$VAR(../../@)',

    'wireless/node.tag' => '$VAR(../../@)',
    'wireless/node.tag/vif/node.tag' => '$VAR(../../../@).$VAR(../../@)',

    'input/node.tag'  => '$VAR(../../@)',
    'tunnel/node.tag' => '$VAR(../../@)',
    'bridge/node.tag' => '$VAR(../../@)',
    'openvpn/node.tag' => '$VAR(../../@)',

    'l2tpv3/node.tag' => '$VAR(../../@)',

    'vxlan/node.tag' => '$VAR(../../@)',

    'wirelessmodem/node.tag' => '$VAR(../../@)',

    'dummy/node.tag' => '$VAR(../../@)'
);

# The subdirectory where the generated templates will go
my $template_subdir = "generated-templates/interfaces";

# The name of the subdir under each interface holding the firewall tree
my $firewall_subdir = "policy";

# The name of the config file we will be writing.
my $node_file = "node.def";

sub mkdir_p {
    my $path = shift;

    return 1 if ( mkdir($path) );

    my $pos = rindex( $path, "/" );
    return unless $pos != -1;
    return unless mkdir_p( substr( $path, 0, $pos ) );
    return mkdir($path);
}

# Generate the template file located at the root of the firewall tree
# under an interface.  This template just provides a help message.
#
sub gen_firewall_template {
    my ($if_tree) = @_;
    my $path = "${template_subdir}/${if_tree}/${firewall_subdir}";

    ( -d $path ) or mkdir_p($path)
      or die "Can't make directory $path: $!";

    open my $tp, '>', "$path/$node_file"
      or die "Can't create $path/$node_file: $!";
    print $tp "help: Policy route options\n";
    close $tp
      or die "Can't write $path/$node_file: $!";
}

# Map a firewall ruleset type into the string that we will use to describe
# it in help messages.
#
my %table_help_hash = (
    "route"      => "IPv4 policy route",
    "ipv6-route" => "IPv6 policy route",
);

my %config_association_hash = (
    "route"      => "\"policy route\"",
    "ipv6-route" => "\"policy ipv6-route\"",
);

# Generate the template file at the leaf of the per-interface firewall tree.
# This template contains all the code to activate or deactivate a firewall
# ruleset on an interface for a particular ruleset type and direction.
#
sub gen_template {
    my ( $if_tree, $table, $if_name ) = @_;

    if ($debug) {
        print "debug: table=$table\n";
    }

    my $template_dir =
      "${template_subdir}/${if_tree}/${firewall_subdir}/${table}";

    if ($debug) {
        print "debug: template_dir=$template_dir\n";
    }

    ( -d $template_dir) or mkdir_p($template_dir)
    or die "Can't make directory $template_dir: $!";

    open my $tp, '>', "${template_dir}/${node_file}"
      or die "Can't open ${template_dir}/${node_file}:$!";

    print $tp <<EOF;
type: txt
help: $table_help_hash{$table} ruleset for interface
allowed: local -a params
	eval "params=(\$(cli-shell-api listNodes policy $table))"
	echo -n "\${params[@]}"
create: ifname=$if_name
	sudo /opt/vyatta/sbin/vyatta-firewall.pl --update-interfaces \\
		update \$ifname in \$VAR(@) $config_association_hash{$table}

update:	ifname=$if_name
	sudo /opt/vyatta/sbin/vyatta-firewall.pl --update-interfaces \\
		update \$ifname in \$VAR(@) $config_association_hash{$table}


delete:	ifname=$if_name
	sudo /opt/vyatta/sbin/vyatta-firewall.pl --update-interfaces \\
		delete \$ifname in \$VAR(@) $config_association_hash{$table}
EOF

    close $tp
      or die "Can't write ${template_dir}/${node_file}:$!";
}

print "Generating policy templates...\n";

foreach my $if_tree ( keys %interface_hash ) {
    my $if_name = $interface_hash{$if_tree};

    if ($debug) {
        print "debug: if_tree=$if_tree if_name=$if_name \n";
    }

    gen_firewall_template($if_tree);
    gen_template( $if_tree, "route", $if_name );
    gen_template( $if_tree, "ipv6-route", $if_name );
}

print "Done.\n";
