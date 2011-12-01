#!/usr/bin/perl
#
# Module: vyatta-fw-global-state-policy.pl
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
# Portions created by Vyatta are Copyright (C) 2011 Vyatta, Inc.
# All Rights Reserved.
#
# Author: Mohit Mehta
# Date: November 2011
# Description: Script for setting/changing/removing global FW state-policy
#
# **** End License ****
#

use lib "/opt/vyatta/share/perl5";
use warnings;
use strict;
use Switch;
use Vyatta::Config;
use Vyatta::IpTables::Mgr;
use Getopt::Long;
use Sys::Syslog qw(:standard :macros);

# mapping from config node to iptables command
our %cmd_hash = ( 'name'        => '/sbin/iptables',
                  'ipv6-name'   => '/sbin/ip6tables');

# mapping from config node to iptables/ip6tables table
our %table_hash = ( 'name'        => 'filter',
                    'ipv6-name'   => 'filter');

# pre FW hooks in iptables' INPUT, OUTPUT and FORWARD chains
our %pre_fw_hooks_hash = ( 'INPUT'   => 'VYATTA_PRE_FW_IN_HOOK',
                           'FORWARD' => 'VYATTA_PRE_FW_FWD_HOOK',
                           'OUTPUT'  => 'VYATTA_PRE_FW_OUT_HOOK');

# post FW hooks in iptables' INPUT, OUTPUT and FORWARD chains
our %post_fw_hooks_hash = ( 'INPUT'   => 'VYATTA_POST_FW_IN_HOOK',
                            'FORWARD' => 'VYATTA_POST_FW_FWD_HOOK',
                            'OUTPUT'  => 'VYATTA_POST_FW_OUT_HOOK');

# state policy chains in iptables' INPUT, OUTPUT and FORWARD chains
our %state_policy_chains_hash = ( 'INPUT'   => 'VYATTA_STATE_POLICY_IN_HOOK',
                                  'FORWARD' => 'VYATTA_STATE_POLICY_FWD_HOOK',
                                  'OUTPUT'  => 'VYATTA_STATE_POLICY_OUT_HOOK');

# state actions
our %state_action_hash = ( 'drop'    => 'DROP',
                           'reject'  => 'REJECT',
                           'accept'  => 'JUMP_TO_INDIVIDUAL_POST_FW_HOOK',
			   'log'     => 'LOG');

# state actions' log abbreviations
our %state_log_abbr_hash = ( 'drop'    => 'D',
                             'reject'  => 'R',
                             'accept'  => 'A');

# imp to maintain order of this array since this is the
# order we want to insert rules into state-policy chains
my @fw_states = ('invalid', 'established', 'related');

# log prefix - FW_STATE_POL-$STATE-$ACTION_ABBREVIATION
my $fw_log_prefix = 'FW-STATE_POL';

# this function performs the following functions:
# 1. sets up VYATTA_FW_*_STATE_POLICY chains i.e. for INPUT, OUTPUT, FORWARD hooks
# 2. adds rules in VYATTA_PRE_FW_*_HOOK hooks to jump to VYATTA_FW_*_STATE_POLICY
sub setup_state_policy {
  my ($cmd, $error);

  foreach my $tree (keys %cmd_hash) {
    foreach my $iptables_chain (keys %state_policy_chains_hash) {
      # create VYATTA_FW_*_STATE_POLICY chains
      $error = Vyatta::IpTables::Mgr::create_ipt_chain ($cmd_hash{$tree},
$table_hash{$tree}, $state_policy_chains_hash{$iptables_chain});
      return ($error, ) if $error;

      # append RETURN to VYATTA_FW_*_STATE_POLICY chains
      $error = Vyatta::IpTables::Mgr::append_ipt_rule ($cmd_hash{$tree},
$table_hash{$tree}, $state_policy_chains_hash{$iptables_chain}, 'RETURN');
      return ($error, ) if $error;

      # insert rule in VYATTA_PRE_FW_*_HOOK to jump to VYATTA_FW_*_STATE_POLICY
      $error = Vyatta::IpTables::Mgr::insert_ipt_rule ($cmd_hash{$tree},
$table_hash{$tree}, $pre_fw_hooks_hash{$iptables_chain}, 
$state_policy_chains_hash{$iptables_chain});
      return ($error, ) if $error;
    }
  }

  return;
}

# this function reverts the operations done in setup_state_policy():
# 1. removes rules from VYATTA_PRE_FW_*_HOOK hooks to jump to VYATTA_FW_*_STATE_POLICY
# 2. deletes VYATTA_FW_STATE_POLICY chains i.e. for IN, OUT, FWD hooks
sub teardown_state_policy {
  my ($cmd, $error);

  foreach my $tree (keys %cmd_hash) {
    foreach my $iptables_chain (keys %state_policy_chains_hash) {
      # remove rule in VYATTA_PRE_FW_*_HOOK to jump to VYATTA_FW_*_STATE_POLICY
      $error = Vyatta::IpTables::Mgr::delete_ipt_rule ($cmd_hash{$tree}, 
$table_hash{$tree}, $pre_fw_hooks_hash{$iptables_chain}, 
$state_policy_chains_hash{$iptables_chain});
      return ($error, ) if $error;

      # flush all rules from VYATTA_FW_*_STATE_POLICY chains
      $error = Vyatta::IpTables::Mgr::flush_ipt_chain($cmd_hash{$tree}, 
$table_hash{$tree}, $state_policy_chains_hash{$iptables_chain});
      return ($error, ) if $error;

      # delete VYATTA_FW_*_STATE_POLICY chains
      $error = Vyatta::IpTables::Mgr::delete_ipt_chain($cmd_hash{$tree},
$table_hash{$tree}, $state_policy_chains_hash{$iptables_chain});
      return ($error, ) if $error;
    }
  }

  return;
}

# set all state actions and their log rules
# Flush all previous rules and then set rules in the following order:
# INVALID - log rule followed by action rule
# ESTABLISHED - log rule followed by action rule
# RELATED - log rule followed by action rule
# Keep appending rules and then append RETURN rule at the end
sub set_state_actions {
  my ($cmd, $error);

  my $config = new Vyatta::Config;
  # skip steps below if state-policy deleted
  return if (!defined $config->exists("firewall state-policy"));

  # flush state_policy_chains
  foreach my $tree (keys %cmd_hash) {
    foreach my $iptables_chain (keys %state_policy_chains_hash) {
      # flush all rules from VYATTA_FW_*_STATE_POLICY chains
      $error = Vyatta::IpTables::Mgr::flush_ipt_chain($cmd_hash{$tree},
$table_hash{$tree}, $state_policy_chains_hash{$iptables_chain});
      return ($error, ) if $error;
    }
  }

  # check config for each states in this order: invalid, established, related
  # insert rules for log and action for each state
  foreach my $state (@fw_states) {
    $config->setLevel("firewall state-policy $state");
    my ($action, $log_enabled) = (undef, undef);
    $log_enabled = $config->exists("log enable");
    $action = $config->returnValue("action");
    my $uc_action = uc($action) if defined $action;
    my $uc_state = uc ($state) if defined $state;
    if (defined $log_enabled) {
      foreach my $tree (keys %cmd_hash) {
        foreach my $iptables_chain (keys %state_policy_chains_hash) {
          # insert rule in VYATTA_FW_*_STATE_POLICY
          my $jump_target = "LOG --log-prefix \"[$fw_log_prefix-$uc_state-$state_log_abbr_hash{$action}]\" ";
          $error = Vyatta::IpTables::Mgr::append_ipt_rule ($cmd_hash{$tree},
$table_hash{$tree}, $state_policy_chains_hash{$iptables_chain}, $jump_target, "-m state --state $uc_state");
          return ($error, ) if $error;
        }
      }
    }
    if (defined $action) {
      foreach my $tree (keys %cmd_hash) {
        foreach my $iptables_chain (keys %state_policy_chains_hash) {
          # if action is accept then jump target shold be post_fw_hooks post_fw_hooks_hash
          if ($action eq 'accept') {
            $error = Vyatta::IpTables::Mgr::append_ipt_rule ($cmd_hash{$tree},
$table_hash{$tree}, $state_policy_chains_hash{$iptables_chain}, 
$post_fw_hooks_hash{$iptables_chain}, "-m state --state $uc_state");
          } else {
            $error = Vyatta::IpTables::Mgr::append_ipt_rule ($cmd_hash{$tree},
$table_hash{$tree}, $state_policy_chains_hash{$iptables_chain}, 
$uc_action, "-m state --state $uc_state");
          }
          return ($error, ) if $error;
        }
      }
    }
  }

  # append rule with target RETURN at the end
  foreach my $tree (keys %cmd_hash) {
    foreach my $iptables_chain (keys %state_policy_chains_hash) {
      # append RETURN to VYATTA_FW_*_STATE_POLICY chains
      $error = Vyatta::IpTables::Mgr::append_ipt_rule ($cmd_hash{$tree},
$table_hash{$tree}, $state_policy_chains_hash{$iptables_chain}, 'RETURN');
      return ($error, ) if $error;
    }
  }

  return;
}

sub enable_disable_conntrack {
  my ($cmd, $error);

  my $conntrack_enabled = 'false';
  foreach my $state (@fw_states) {
    my $config = new Vyatta::Config;
    $config->setLevel("firewall state-policy $state");
    my ($action) = (undef);
    $action = $config->returnOrigValue("action");
    if (defined $action) {
      $conntrack_enabled = 'true';
      last;
    }
  }
  if ($conntrack_enabled eq 'true') {
    foreach my $tree (keys %cmd_hash) {
      Vyatta::IpTables::Mgr::ipt_disable_conntrack($cmd_hash{$tree}, 'FW_STATE_POLICY_CONNTRACK');
    }
  }

  my $enable_conntrack = 'false';
  foreach my $state (@fw_states) {
    my $config = new Vyatta::Config;
    $config->setLevel("firewall state-policy $state");
    my ($action) = (undef);
    $action = $config->returnValue("action");
    if (defined $action) {
      $enable_conntrack = 'true';
      last;
    }
  }
  if ($enable_conntrack eq 'true') {
    foreach my $tree (keys %cmd_hash) {
      Vyatta::IpTables::Mgr::ipt_enable_conntrack($cmd_hash{$tree}, 'FW_STATE_POLICY_CONNTRACK');
    }
  }

  return;
}

sub state_policy_validity_checks {
  my ($cmd, $error);

  foreach my $state (@fw_states) {
    my $config = new Vyatta::Config;
    $config->setLevel("firewall state-policy $state");
    my ($action, $log_enabled) = (undef, undef);
    $log_enabled = $config->exists("log enable");
    $action = $config->returnValue("action");
    if (defined $log_enabled && !defined $action) {
      $error = "log enabled but action not configured for state: $state\n" . 
"action is required to log packets\n";
      return $error;
    }
  }

  return;
}

#
# main
#

my ($action, $state, $state_action);

GetOptions("action=s"         => \$action,
	   "state=s"          => \$state,
           "state-action=s"   => \$state_action,
);

die "undefined action" if ! defined $action;

my ($error, $warning);

($error, $warning) = setup_state_policy() if $action eq 'setup-state-policy';

($error, $warning) = teardown_state_policy() if $action eq 'teardown-state-policy';

($error, $warning) = set_state_actions() if $action eq 'set-state-actions';

($error, $warning) = enable_disable_conntrack($state) if $action eq 'enable-disable-conntrack';

($error, $warning) = state_policy_validity_checks($state) if $action eq 'state-policy-validity-checks';

if (defined $warning) {
    print "$warning\n";
}

if (defined $error) {
    print "$error\n";
    exit 1;
}

exit 0;

# end of file
