#!/usr/bin/perl
#
# Module: vyatta-firewall-trap.pl
# Description: Generate SNMP traps when firewall config changes
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
# Portions created by Vyatta are Copyright (C) 2013 Vyatta, Inc.
# All Rights Reserved.
#
# **** End License ****
#

use lib "/opt/vyatta/share/perl5";
use warnings;
use strict;
use English;
use Vyatta::Config;
use Getopt::Long;
use Sys::Syslog qw(:standard :macros);
use SNMP;

# Maps node status to OID value
my %change_type_hash = ( 'unknown' => 0,
                         'added'   => 1,
                         'deleted' => 2,
                         'changed' => 3 );

# Array of Net::SNMP::TrapSession to send traps
my @snmp_sessions;

# Enable printing debug output to stdout.
my $debug_flag = 0;

# Enable sending debug output to syslog.
my $syslog_flag = 1;

my $cfglevel;

GetOptions("level=s"      => \$cfglevel,
           "debug"        => \$debug_flag,
           "syslog"       => \$syslog_flag
);

openlog("firewall-trap", "pid", "user") if $syslog_flag;

# If debugging, lets see more SNMP outpyt
$SNMP::debugging = $debug_flag;

sub log_msg {
  my $message = shift;

  chomp($message);
  print "DEBUG: $message\n" if $debug_flag;
  syslog(LOG_NOTICE, "%s", $message) if $syslog_flag;
}

sub log_err {
  my $message = shift;

  chomp($message);
  print "DEBUG: $message\n" if $debug_flag;
  syslog(LOG_ERR, "%s", $message) if $syslog_flag;
}

# Initializes an SNMP session for each configured trap-target
#
# Returns:
#  undef if no trap-targets
#  # of trap targets
sub snmp_init {
    my ( $config ) = @_;
    my $trap_session;
    my @trap_targets;
    my $level_pfx = "service snmp trap-target";

    @trap_targets = $config->listNodes($level_pfx);
    return unless @trap_targets;

    foreach my $trap_target (@trap_targets) {
        my $port = $config->returnValue("$level_pfx $trap_target port");
        my $community
            = $config->returnValue("$level_pfx $trap_target community");

        $trap_target .= ":$port" if $port;
        $community = "public" unless $community;

        my ($snmp_session, $error)  = new SNMP::TrapSession(
            DestHost  => "$trap_target",
            Community => $community,
            Version   => '2c'
            );
        if (!defined $snmp_session) {
            log_err "Unable to open trap session for $trap_target community";
        } else {
            push(@snmp_sessions, $snmp_session);
        }
    }
    return scalar (@trap_targets);
}

sub trap_send {
    my ($change_type, $prev, $curr) = @_;
    my $trap_name = 'VYATTA-TRAP-MIB::mgmtEventTrap';
    my $mgmtEventUser = 'mgmtEventUser';
    my $mgmtEventSource = 'mgmtEventSource';
    my $mgmtEventType = 'mgmtEventType';
    my $mgmtEventPrevCfg = 'mgmtEventPrevCfg';
    my $mgmtEventCurrCfg = 'mgmtEventCurrCfg';
    my $event_source = 1; # firewall
    my $event_name = getpwuid($UID) . "($UID)";

    $change_type = $change_type_hash{$change_type};
    $change_type = 0 unless $change_type;
    log_msg "trap_send: user = $event_name";
    log_msg "trap_send: mgmtEventType = $change_type";
    log_msg "trap_send: mgmtEventPrevCfg = $prev" if $prev;
    log_msg "trap_send: mgmtEventCurrCfg = $curr" if $curr;

    foreach my $snmp_session (@snmp_sessions) {
        # uptime is auto-populated if not explicitly set
        # trap does not like empty strings so only send oids with values
        if ($change_type == $change_type_hash{'added'}) {
            $snmp_session->trap(
                oid => $trap_name,
                [[$mgmtEventUser, 0, $event_name],
                 [$mgmtEventSource, 0, $event_source],
                 [$mgmtEventType, 0, $change_type],
                 [$mgmtEventCurrCfg, 0, $curr]]);
        } elsif ($change_type == $change_type_hash{'deleted'}) {
            $snmp_session->trap(
                oid => $trap_name,
                [[$mgmtEventUser, 0, $event_name],
                 [$mgmtEventSource, 0, $event_source],
                 [$mgmtEventType, 0, $change_type],
                 [$mgmtEventPrevCfg, 0, $prev]]);
        } elsif ($change_type == $change_type_hash{'changed'}) {
            $snmp_session->trap(
                oid => $trap_name,
                [[$mgmtEventUser, 0, $event_name],
                 [$mgmtEventSource, 0, $event_source],
                 [$mgmtEventType, 0, $change_type],
                 [$mgmtEventPrevCfg, 0, $prev],
                 [$mgmtEventCurrCfg, 0, $curr]]);
        } else {
            $snmp_session->trap(
                oid => $trap_name,
                [[$mgmtEventUser, 0, $event_name],
                 [$mgmtEventSource, 0, $event_source],
                 [$mgmtEventType, 0, $change_type]]);
        }
    }
}

sub leaf_trap {
  my ($config, $change_type, $level) = @_;
  my ($prev, $curr);

  if (($change_type eq "deleted") || ($change_type eq "changed")) {
    $prev = $config->returnOrigValue("$level");
    chomp($prev);
    $prev = "$level $prev" if length($prev);
  }

  if (($change_type eq "added") || ($change_type eq "changed")) {
    $curr = $config->returnValue("$level");
    chomp($curr);
    $curr = "$level $curr" if length($curr);
  }
  trap_send($change_type, $prev, $curr);
}

sub leaf_multi_trap {
  my ($config, $change_type, $level) = @_;
  my (@prev, @curr);
  my ($prevstr, $currstr);

  if (($change_type eq "deleted") || ($change_type eq "changed")) {
    @prev = $config->returnOrigValues("$level");
    $prevstr = "$level " . join(' ', @prev);
    chomp($prevstr);
  }

  if (($change_type eq "added") || ($change_type eq "changed")) {
    @curr = $config->returnValues("$level");
    $currstr = "$level " . join(' ', @curr);
    chomp($currstr);
  }
  trap_send($change_type, $prevstr, $currstr);
}

sub leaf_valueless_trap {
  my ($config, $change_type, $level) = @_;
  my ($prev, $curr);

  chomp($level);
  $prev = "$level" if ($change_type eq "deleted");
  $curr = "$level" if ($change_type eq "added");
  trap_send($change_type, $prev, $curr);
}

sub firewall_cfg_trap {
    my ($config, $level) = @_;
    my %node_status = $config->listNodeStatus("$level");

    foreach my $node (keys %node_status) {
        next if $node_status{$node} eq 'static';
        if ($config->isTagNode("$level $node")) {
            firewall_cfg_trap($config, "$level $node");
        } elsif ($config->isLeafNode("$level $node")) {
            if ($config->isMultiNode("$level $node")) {
                leaf_multi_trap($config, $node_status{$node}, "$level $node");
            } else {
                leaf_trap($config, $node_status{$node}, "$level $node");
            }
        } elsif ($config->hasTmplChildren("$level $node")) {
            # Valueless node with children, descend tree recursively
            firewall_cfg_trap($config, "$level $node");
        } else {
            # Valueless leaf node
            leaf_valueless_trap($config, $node_status{$node}, "$level $node");
        }
    }
}

# Special handling for the top "firewall" config node.
#
# Only processes leaf nodes. Ideally the general purpose traversal
# function (firewall_cfg_trap), could detect crossing priority groups
# like the cstore code does. But this is easier.
sub firewall_cfg_leaf_trap {
    my ($config, $level) = @_;
    my %node_status = $config->listNodeStatus("$level");

    foreach my $node (keys %node_status) {
        next if $node_status{$node} eq 'static';
        if ($config->isLeafNode("$level $node")) {
            if ($config->isMultiNode("$level $node")) {
                leaf_multi_trap($config, $node_status{$node}, "$level $node");
            } else {
                leaf_trap($config, $node_status{$node}, "$level $node");
            }
        } elsif ($config->isTagNode("$level $node")) {
            next;  # Skip tag node
        } elsif ($config->hasTmplChildren("$level $node")) {
            next;  # Valueless node with children, skip
        } else {
            # Valueless leaf node
            leaf_valueless_trap($config, $node_status{$node}, "$level $node");
        }
    }
}

sub is_trap_enabled {
    my ($config) = @_;
    my $level = 'firewall config-trap';
    my $value;

    if ($config->existsOrig($level)) {
        $value = $config->returnOrigValue($level);
    } else {
        my @tmpl = $config->parseTmpl($level);
        $value = $tmpl[2]; # default value
    }
    return $value eq 'enable';
}

my $config = new Vyatta::Config;

# Detect if firewall config traps are enabled
exit 0 if ! is_trap_enabled($config);

# Detect system startup  (i.e., no snmpd running) and just exit.
my $snmpd_service = `/usr/sbin/invoke-rc.d snmpd status 2> /dev/null`;
exit 0 if (! $snmpd_service =~ m/snmpd is running/);

# If no trap-targets configured just exit.
exit 0 unless snmp_init($config);

if (defined $cfglevel) {
    if ($cfglevel eq 'firewall') {
        # Special handling for the top "firewall" node.
        firewall_cfg_leaf_trap($config, "$cfglevel");
    } else {
        firewall_cfg_trap($config, "$cfglevel");
    }
}

exit 0;
