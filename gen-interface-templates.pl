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
    'adsl/node.tag/pvc/node.tag/bridged-ethernet'     => '$VAR(../../../../../@)',
    'adsl/node.tag/pvc/node.tag/classical-ipoa'       => '$VAR(../../../../../@)',
    'adsl/node.tag/pvc/node.tag/pppoa/node.tag'       => 'pppoa$VAR(../../../@)',
    'adsl/node.tag/pvc/node.tag/pppoe/node.tag'       => 'pppoe$VAR(../../../@)',

    'bonding/node.tag'                                => '$VAR(../../../@)',
    'bonding/node.tag/vif/node.tag'                   => '$VAR(../../../../@).$VAR(../../../@)',
    'bonding/node.tag/vif-s/node.tag'                 => '$VAR(../../../../@).$VAR(../../../@)',
    'bonding/node.tag/vif-s/node.tag/vif-c/node.tag'  => '$VAR(../../../../@).$VAR(../../../@).$VAR(../../@)',

    'ethernet/node.tag'                               => '$VAR(../../../@)',
    'ethernet/node.tag/pppoe/node.tag'                => 'pppoe$VAR(../../../@)',
    'ethernet/node.tag/vif/node.tag'                  => '$VAR(../../../../@).$VAR(../../../@)',
    'ethernet/node.tag/vif/node.tag/pppoe/node.tag'   => 'pppoe$VAR(../../../@)',
    'ethernet/node.tag/vif-s/node.tag'                => '$VAR(../../../../@).$VAR(../../../@)',
    'ethernet/node.tag/vif-s/node.tag/vif-c/node.tag' => '$VAR(../../../../@).$VAR(../../../@).$VAR(../../@)',

    'pseudo-ethernet/node.tag'                               => '$VAR(../../../@)',
    'pseudo-ethernet/node.tag/vif/node.tag'                  => '$VAR(../../../../@).$VAR(../../../@)',
    'pseudo-ethernet/node.tag/vif-s/node.tag'                => '$VAR(../../../../@).$VAR(../../../@)',
    'pseudo-ethernet/node.tag/vif-s/node.tag/vif-c/node.tag' => '$VAR(../../../../@).$VAR(../../../@).$VAR(../../@)',

    'wireless/node.tag' => '$VAR(../../../@)',
    'wireless/node.tag/vif/node.tag' => '$VAR(../../../../@).$VAR(../../../@)',

    'input/node.tag'  => '$VAR(../../../@)',
    'tunnel/node.tag' => '$VAR(../../../@)',
    'vti/node.tag' => '$VAR(../../../@)',
    'bridge/node.tag' => '$VAR(../../../@)',
    'openvpn/node.tag' => '$VAR(../../../@)',

    'l2tpv3/node.tag'  => '$VAR(../../../@)',

    'vxlan/node.tag'   => '$VAR(../../../@)',

    'multilink/node.tag/vif/node.tag' => '$VAR(../../../../@)',

    'serial/node.tag/cisco-hdlc/vif/node.tag' =>
      '$VAR(../../../../../@).$VAR(../../../@)',
    'serial/node.tag/frame-relay/vif/node.tag' =>
      '$VAR(../../../../../@).$VAR(../../../@)',
    'serial/node.tag/ppp/vif/node.tag' =>
      '$VAR(../../../../../@).$VAR(../../../@)',

    'wirelessmodem/node.tag' => '$VAR(../../../@)',
);

# Firewall node hashes
my %firewall_hash = (
    'adsl/node.tag/pvc/node.tag/bridged-ethernet' => 'adsl $VAR(../../../@) pvc $VAR(../../@) bridged-ethernet',
    'adsl/node.tag/pvc/node.tag/classical-ipoa' => 'adsl $VAR(../../../@) pvc $VAR(../../@) classical-ipoa',
    'adsl/node.tag/pvc/node.tag/pppoa/node.tag' => 'adsl $VAR(../../../@) pvc $VAR(../../@) pppoa $VAR(../@)',
    'adsl/node.tag/pvc/node.tag/pppoe/node.tag' => 'adsl $VAR(../../../@) pvc $VAR(../../@) pppoe $VAR(../@)',
    'bonding/node.tag' => 'bonding $VAR(../@)',
    'bonding/node.tag/vif/node.tag' => 'bonding $VAR(../../../@) vif $VAR(../@)',
    'bonding/node.tag/vif-s/node.tag' => 'bonding $VAR(../../../@) vif-s $VAR(../@)',
    'bonding/node.tag/vif-s/node.tag/vif-c/node.tag' => 'bonding $VAR(../../../../@) vif-s $VAR(../../@) vif-c $VAR(../@)',
    'bridge/node.tag' => 'bridge $VAR(../@)',
    'ethernet/node.tag' => 'ethernet $VAR(../@)',
    'ethernet/node.tag/pppoa/node.tag' => 'ethernet $VAR(../../@) pppoa $VAR(../@)',
    'ethernet/node.tag/pppoe/node.tag' => 'ethernet $VAR(../../@) pppoe $VAR(../@)',
    'ethernet/node.tag/vif/node.tag' => 'ethernet $VAR(../../../@) vif $VAR(../@)',
    'ethernet/node.tag/vif-s/node.tag' => 'ethernet $VAR(../../../@) vif-s $VAR(../@)',
    'ethernet/node.tag/vif-s/node.tag/vif-c/node.tag' => 'ethernet $VAR(../../../../@) vif-s $VAR(../../@) vif-c $VAR(../@)',
    'ethernet/node.tag/vif/node.tag/pppoe/node.tag' => 'ethernet $VAR(../../../../@) vif $VAR(../../@) pppoe $VAR(../@)',
    'input/node.tag' => 'input $VAR(../@)',
    'multilink/node.tag/vif/node.tag' => 'multilink $VAR(../../../@) vif $VAR(../@)',
    'openvpn/node.tag' => 'openvpn $VAR(../@)',
    'pseudo-ethernet/node.tag' => 'pseudo-ethernet $VAR(../@)',
    'pseudo-ethernet/node.tag/vif/node.tag' => 'pseudo-ethernet $VAR(../../../@) vif $VAR(../@)',
    'pseudo-ethernet/node.tag/vif-s/node.tag' => 'pseudo-ethernet $VAR(../../../@) vif-s $VAR(../@)',
    'pseudo-ethernet/node.tag/vif-s/node.tag/vif-c/node.tag' => 'pseudo-ethernet $VAR(../../../../@) vif-s $VAR(../../@) vif-c $VAR(../@)',
    'serial/node.tag/cisco-hdlc/vif/node.tag' => 'serial $VAR(../../../@) cisco-hdlc vif $VAR(../@)',
    'serial/node.tag/frame-relay/vif/node.tag' => 'serial $VAR(../../../@) frame-relay vif $VAR(../@)',
    'serial/node.tag/ppp/vif/node.tag' => 'serial $VAR(../../../@) ppp vif $VAR(../@)',
    'tunnel/node.tag' => 'tunnel $VAR(../@)',
    'vti/node.tag' => 'vti $VAR(../@)',
    'wireless/node.tag' => 'wireless $VAR(../@)',
    'wireless/node.tag/vif/node.tag' => 'wireless $VAR(../../../@) vif $VAR(../@)',
    'wirelessmodem/node.tag' => 'wirelessmodem $VAR(../@)',
    'l2tpv3/node.tag' => 'l2tpv3 $VAR(../@)',
    'vxlan/node.tag' => 'vxlan $VAR(../@)'
);

# Hash table to check if the priority needs to set @ root
# of the node.def which is generated.
my %interface_prio = (
    'vti/node.tag'                              => '901',
);

# The subdirectory where the generated templates will go
my $template_subdir = "generated-templates/interfaces";

# The name of the subdir under each interface holding the firewall tree
my $firewall_subdir = "firewall";

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
    if (exists $interface_prio{ $if_tree }) {
        print $tp "priority: $interface_prio{ $if_tree }\n";
    }
    print $tp "help: Firewall options\n";
    die "ERROR: No firewall hash for ${if_tree}" unless $firewall_hash{"${if_tree}"};
    print $tp 'end: ${vyatta_sbindir}/vyatta-firewall-trap.pl --level="interfaces ';
    print $tp $firewall_hash{"${if_tree}"} . ' firewall"' . "\n";
    close $tp
      or die "Can't write $path/$node_file: $!";
}

# Map a firewall "direction" into a sub-string that we will use to compose
# the help message.
#
my %direction_help_hash = (
    "in"    => "forwarded packets on inbound interface",
    "out"   => "forwarded packets on outbound interface",
    "local" => "packets destined for this router",
);

# Generate the template file located under the "direction" node in the
# firewall tree under an interface.  This template just provides a help
# message.
#
sub gen_direction_template {
    my ( $if_tree, $direction ) = @_;
    my $path = "${template_subdir}/${if_tree}/${firewall_subdir}/${direction}";

    ( -d $path ) or mkdir_p($path)
      or die "Can't make directory $path: $!";

    open my $tp, '>', "$path/$node_file"
      or die "Can't open $path/$node_file: $!";

    print $tp "help: Ruleset for $direction_help_hash{$direction}\n";
    close $tp
      or die "Can't write $path/$node_file: $!";
}

# Map a firewall "direction" into the term we will use for it in help
# messages.
#
my %direction_term_hash = (
    "in"    => "inbound",
    "out"   => "outbound",
    "local" => "local",
);

# Map a firewall ruleset type into the string that we will use to describe
# it in help messages.
#
my %table_help_hash = (
    "name"        => "IPv4 firewall",
    "ipv6-name"   => "IPv6 firewall",
);

# Generate the template file at the leaf of the per-interface firewall tree.
# This template contains all the code to activate or deactivate a firewall
# ruleset on an interface for a particular ruleset type and direction.
#
sub gen_template {
    my ( $if_tree, $direction, $table, $if_name ) = @_;

    if ($debug) {
        print "debug: table=$table direction=$direction\n";
    }

    my $template_dir =
      "${template_subdir}/${if_tree}/${firewall_subdir}/${direction}/${table}";

    if ($debug) {
        print "debug: template_dir=$template_dir\n";
    }

    ( -d $template_dir) or mkdir_p($template_dir)
	or die "Can't make directory $template_dir: $!";

    open my $tp, '>', "${template_dir}/${node_file}"
      or die "Can't open ${template_dir}/${node_file}:$!";

    my $action = ucfirst($direction_term_hash{$direction});
    print $tp <<EOF;
type: txt
help: $action $table_help_hash{$table} ruleset name for interface
allowed: local -a params
	eval "params=(\$(cli-shell-api listActiveNodes firewall $table))"
	echo -n "\${params[@]}"
create: ifname=$if_name
	sudo /opt/vyatta/sbin/vyatta-firewall.pl --update-interfaces \\
		update \$ifname $direction \$VAR(@) \"firewall $table\"

update:	ifname=$if_name
	sudo /opt/vyatta/sbin/vyatta-firewall.pl --update-interfaces \\
		update \$ifname $direction \$VAR(@) \"firewall $table\"


delete:	ifname=$if_name
	sudo /opt/vyatta/sbin/vyatta-firewall.pl --update-interfaces \\
		delete \$ifname $direction \$VAR(@) \"firewall $table\"
EOF

    close $tp
      or die "Can't write ${template_dir}/${node_file}:$!";
}

# The firewall ruleset types
my @ruleset_tables = ( "name", "ipv6-name" );

# The firewall "directions"
my @ruleset_directions = ( "in", "out", "local" );

print "Generating interface templates...\n";

foreach my $if_tree ( keys %interface_hash ) {
    my $if_name = $interface_hash{$if_tree};

    if ($debug) {
        print "debug: if_tree=$if_tree if_name=$if_name \n";
    }

    gen_firewall_template($if_tree);
    for my $direction (@ruleset_directions) {
        gen_direction_template( $if_tree, $direction );
        foreach my $table (@ruleset_tables) {
            gen_template( $if_tree, $direction, $table, $if_name );
        }
    }
}

print "Done.\n";
