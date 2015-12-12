#
# Module: Vyatta::IpTables::Mgr.pm
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
# Portions created by Vyatta are Copyright (C) 2010 Vyatta, Inc.
# All Rights Reserved.
#
# Author: Stig Thormodsrud
# Date: June 2010
# Description: common iptables routines
#
# **** End License ****
#

package Vyatta::IpTables::Mgr;

use strict;
use warnings;

use base 'Exporter';
our @EXPORT = qw(ipt_find_chain_rule ipt_enable_conntrack
    ipt_disable_conntrack count_iptables_rules
    chain_referenced ipt_get_queue_target
    run_ipt_cmd create_ipt_chain delete_ipt_chain
    flush_ipt_chain insert_ipt_rule append_ipt_rule
    delete_ipt_rule delete_ipt_rulenum ipt_find_comment_rule);

## TODO - in future, we could use perl's libiptc module instead of
## running system commands in the following function for iptables.
## However, that would need integrating the libiptc module into the system
## and also adding other functionality to it, including IPv6 support.
sub run_ipt_cmd {
    my ($cmd) = shift;
    my $error = system("$cmd");

    my $debug = "false";
    my $syslog = "false";
    my $logger = "sudo logger -t Vyatta::IPTables::Mgr -p local0.warn --";

    if ($syslog eq "true") {
        my $func = (caller(1))[3];
        system("$logger [$func] [$cmd] = [$error]");
    }
    if ($debug eq "true") {
        my $func = (caller(1))[3];
        print "\n[$func] [$cmd] = [$error]";
    }
    return $error;
}

sub create_ipt_chain {
    my ($ipt_cmd, $table, $chain) = @_;
    my ($cmd, $error);

    $cmd = "sudo $ipt_cmd -t $table -N $chain";
    $error = run_ipt_cmd($cmd);
    return "create_ipt_chain [$ipt_cmd -t $table -N $chain] failed: [error code - $error]" if $error;

    return;
}

sub flush_ipt_chain {
    my ($ipt_cmd, $table, $chain) = @_;
    my ($cmd, $error);

    $cmd = "sudo $ipt_cmd -t $table -F $chain";
    $error = run_ipt_cmd($cmd);
    return "flush_ipt_chain [$ipt_cmd -t $table -F $chain] failed: [error code - $error]" if $error;

    return;
}

sub delete_ipt_chain {
    my ($ipt_cmd, $table, $chain) = @_;
    my ($cmd, $error);

    $cmd = "sudo $ipt_cmd -t $table -X $chain";
    $error = run_ipt_cmd($cmd);
    return "delete_ipt_chain [$ipt_cmd -t $table -X $chain] failed: [error code - $error]" if $error;

    return;
}

sub insert_ipt_rule {
    my ($ipt_cmd, $table, $chain, $jump_target, $insert_num, $append_options) = @_;
    my ($cmd, $error);

    $insert_num = 1 if (!defined $insert_num);
    $cmd = "sudo $ipt_cmd -t $table -I $chain $insert_num -j $jump_target ";
    $cmd .= $append_options if defined $append_options;
    $error = run_ipt_cmd($cmd);
    return "insert_ipt_rule [$ipt_cmd -t $table -I $chain $insert_num -j $jump_target] failed: [error code - $error]" if $error;

    return;
}

sub append_ipt_rule {
    my ($ipt_cmd, $table, $chain, $jump_target, $append_options) = @_;
    my ($cmd, $error);

    $cmd = "sudo $ipt_cmd -t $table -A $chain -j $jump_target ";
    $cmd .= $append_options if defined $append_options;
    $error = run_ipt_cmd($cmd);
    return "append_ipt_rule [$ipt_cmd -t $table -A $chain -j $jump_target] failed: [error code - $error]" if $error;

    return;
}

# delete rule based on jump target. should only be used if jump_target is unique in that chain
sub delete_ipt_rule {
    my ($ipt_cmd, $table, $chain, $jump_target) = @_;
    my ($cmd, $error);

    $cmd = "sudo $ipt_cmd -t $table -D $chain -j $jump_target";
    $error = run_ipt_cmd($cmd);
    return "delete_ipt_rule [$ipt_cmd -t $table -D $chain -j $jump_target] failed: [error code - $error]" if $error;

    return;
}

# delete rule based on rule number
sub delete_ipt_rulenum {
    my ($ipt_cmd, $table, $chain, $delete_num) = @_;
    my ($cmd, $error);

    $cmd = "sudo $ipt_cmd -t $table -D $chain $delete_num";
    $error = run_ipt_cmd($cmd);
    return "delete_ipt_rulenum [$ipt_cmd -t $table -D $chain $delete_num] failed: [error code - $error]" if $error;

    return;
}

# searches and returns first found rule based on jump target
sub ipt_find_chain_rule {
    my ($iptables_cmd, $table, $chain, $search) = @_;

    my ($num, $chain2) = (undef, undef);
    my $cmd = "$iptables_cmd -t $table -L $chain -vn --line";
    my @lines = `sudo $cmd 2> /dev/null | egrep ^[0-9]`;
    if (scalar(@lines) < 1) {
        return;
    }
    foreach my $line (@lines) {
        ($num, undef, undef, $chain2) = split /\s+/, $line;
        last if $chain2 eq $search;
        ($num, $chain2) = (undef, undef);
    }

    return $num if defined $num;
    return;
}

# searches and returns first found rule based on matching text in rule comment
sub ipt_find_comment_rule {
    my ($iptables_cmd, $table, $chain, $search) = @_;

    my $cmd = "$iptables_cmd -t $table -L $chain -vn --line";
    my @lines = `sudo $cmd 2> /dev/null | egrep ^[0-9]`;
    if (scalar(@lines) < 1) {
        return;
    }

    my ($num, $rule_txt, $comment) = (undef, undef);
    foreach my $line (@lines) {
        ($rule_txt, $comment) = split /\/\*/, $line;

        #print "rule_txt : $rule_txt, comment : $comment\n";
        if (defined $comment && $comment =~ m/$search/) {

            #print "found $search in $comment \n";
            ($num) = split /\s+/, $rule_txt if defined $rule_txt;
            return $num;
        }
        ($rule_txt, $comment) = (undef, undef);
    }
    return;
}
my %conntrack_hook_hash =(
    'PREROUTING' => 'VYATTA_CT_PREROUTING_HOOK',
    'OUTPUT'     => 'VYATTA_CT_OUTPUT_HOOK',
);

sub ipt_enable_conntrack {
    my ($iptables_cmd, $chain) = @_;
    my $hookCtHelper = 'false';

    if (($chain eq 'FW_CONNTRACK') or ($chain eq 'NAT_CONNTRACK')) {
        $hookCtHelper = 'true';
    }

    system("sudo $iptables_cmd -t raw -L $chain -n >& /dev/null");
    if ($? >> 8) {

        # chain does not exist yet. set up conntrack.
        system("sudo $iptables_cmd -t raw -N $chain");
        system("sudo $iptables_cmd -t raw -A $chain -j ACCEPT");

        foreach my $label ('PREROUTING', 'OUTPUT') {
            my $index;
            my $conntrack_hook = $conntrack_hook_hash{$label};
            $index = ipt_find_chain_rule($iptables_cmd, 'raw',$label, $conntrack_hook);
            if (!defined($index)) {
                print "Error: unable to find [$label] [$conntrack_hook]\n";
                return 1;
            }
            $index++;
            system("sudo $iptables_cmd -t raw -I $label $index -j $chain");

            if ($hookCtHelper eq 'true') {

                # we want helper hook only for Firewall / NAT.
                $conntrack_hook = "VYATTA_CT_HELPER";
                $index = ipt_find_chain_rule($iptables_cmd, 'raw',$label, $conntrack_hook);
                if (!defined($index)) {

                    # this index does not change now but maybe later we change it, so being defensive.
                    my $cttimeout_index = ipt_find_chain_rule($iptables_cmd, 'raw', $label, "VYATTA_CT_TIMEOUT");
                    if (defined($cttimeout_index)) {

                        # $cttimeout_index++; fixing 8173
                        # currently we have cttimeout at 1 index, it might change in future.
                        # helper chain should be before timeout chain
                        system("sudo $iptables_cmd -t raw -I $label $cttimeout_index -j VYATTA_CT_HELPER");
                    }
                }
            }
        }
    }
    return 0;
}

sub remove_cthelper_hook {
    my ($iptables_cmd, $label, $chain) =@_;

    #label is PREROUTING / OUTPUT, chain is FW_CONNTRACK/NAT_CONNTRACK etc.
    my $index;

    # find if we need to remove VYATTA_CT_HELPER
    my $cthelper_index = ipt_find_chain_rule($iptables_cmd, 'raw',$label, 'VYATTA_CT_HELPER');
    if(!defined($cthelper_index)) {

        # not an error: this hook is only for FW / NAT
        return 0;
    }

    # if this chain is FW_CONNTRACK, look if NAT is using it, else remove
    if ($chain eq 'FW_CONNTRACK') {
        $index = ipt_find_chain_rule($iptables_cmd, 'raw',$label, 'NAT_CONNTRACK');
        if (!defined($index)) {

            # NAT, only other user of helpers, not enabled, can remove VYATTA_CT_HELPER
            system("sudo $iptables_cmd -t raw -D $label $cthelper_index");
            return 0;
        }
    } elsif ($chain eq 'NAT_CONNTRACK') {
        $index = ipt_find_chain_rule($iptables_cmd, 'raw',$label, 'FW_CONNTRACK');
        if (!defined($index)) {

            # Firewall, only other user of helpers, not enabled, can remove VYATTA_CT_HELPER
            system("sudo $iptables_cmd -t raw -D $label $cthelper_index");
            return 0;
        }
    }
}

sub ipt_disable_conntrack {
    my ($iptables_cmd, $chain) = @_;

    my $debug = 0;
    my @lines;
    foreach my $label ('PREROUTING', 'OUTPUT') {
        my $index;
        my $conntrack_hook = $conntrack_hook_hash{$label};
        $index = ipt_find_chain_rule($iptables_cmd, 'raw',$label, $chain);
        if (!defined($index)) {
            if ($debug > 0) {
                print "Error: ipt_disable_conntrack failed to find ". "[$label][$chain]\n";
            }
            return 1;
        }
        system("sudo $iptables_cmd -t raw -D $label $index");

        remove_cthelper_hook($iptables_cmd, $label, $chain);
    }

    system("sudo $iptables_cmd -t raw -F $chain >& /dev/null");
    system("sudo $iptables_cmd -t raw -X $chain >& /dev/null");

    return 0;
}

my %queue_target_hash =(
    'SNORT'     => 'NFQUEUE',
    'VG_HTTPS'  => 'NFQUEUE --queue-num 1',
);

sub ipt_get_queue_target {
    my ($app) = @_;

    my $target = $queue_target_hash{$app};
    return $target;
}

sub count_iptables_rules {
    my ($iptables_cmd, $table, $chain) = @_;

    my $cmd = "$iptables_cmd -t $table -L $chain -n --line";
    my @lines = `sudo $cmd 2> /dev/null`;
    my $cnt = 0;
    foreach my $line (@lines) {
        $cnt++ if $line =~ /^\d/;
    }
    return $cnt;
}

sub chain_referenced {
    my ($table, $chain, $iptables_cmd) = @_;

    my $cmd  = "$iptables_cmd -t $table -n -L $chain";
    my $line = `sudo $cmd 2>/dev/null |head -n1`;
    chomp $line;
    my $found = 0;
    if ($line =~ m/^Chain $chain \((\d+) references\)$/) {
        if ($1 > 0) {
            $found = 1;
        }
    }
    return $found;
}

1;
