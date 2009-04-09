#!/usr/bin/perl

use lib "/opt/vyatta/share/perl5";
use warnings;
use strict;

use Vyatta::Config;
use Vyatta::IpTables::Rule;
use Vyatta::IpTables::AddressFilter;
use Getopt::Long;

# Send output of shell commands to syslog for debugging and so that
# the user is not confused by it.  Log at debug level, which is supressed
# by default, so that we don't unnecessarily fill up the syslog file.
my $logger = 'logger -t firewall-cfg -p local0.debug --';

# Enable printing debug output to stdout.
my $debug_flag = 0;

# Enable sending debug output to syslog.
my $syslog_flag = 0;

my @updateints = ();
my ($setup, $teardown, $updaterules);

GetOptions("setup"             => \$setup, 
           "teardown"          => \$teardown,
 	   "update-rules"      => \$updaterules,
	   "update-interfaces=s{5}" => \@updateints,
           "debug"             => \$debug_flag,
           "syslog"            => \$syslog_flag
);

# mapping from config node to iptables/ip6tables table
my %table_hash = ( 'name'        => 'filter',
		   'ipv6-name'   => 'filter',
                   'modify'      => 'mangle',
                   'ipv6-modify' => 'mangle' );

# mapping from config node to iptables command.  Note that this table
# has the same keys as %table hash, so a loop iterating through the 
# keys of %table_hash can use the same keys to find the value associated
# with the key in this table.
my %cmd_hash = ( 'name'        => 'iptables',
		 'ipv6-name'   => 'ip6tables',
		 'modify'      => 'iptables',
                 'ipv6-modify' => 'ip6tables');

# mapping from config node to IP version string.
my %ip_version_hash = ( 'name'        => 'ipv4',
                        'ipv6-name'   => 'ipv6',
                        'modify'      => 'ipv4',
                        'ipv6-modify' => 'ipv6');

# mapping from firewall tree to builtin chain for input
my %inhook_hash =  ( 'filter' => 'FORWARD',
	   	     'mangle' => 'PREROUTING' );

# mapping from firewall tree to builtin chain for output
my %outhook_hash = ( 'filter' => 'FORWARD',
	   	     'mangle' => 'POSTROUTING' );

# mapping from vyatta 'default-policy' to iptables jump target
my %policy_hash = ( 'drop'    => 'DROP',
                    'accept'  => 'RETURN' );

sub other_table {
  my $this = shift;
  return (($this eq 'filter') ? 'mangle' : 'filter');
}

if (defined $setup) {
  setup_iptables('iptables');
  setup_iptables('ip6tables');
  exit 0;
}

my $update_zero_count = 0;
if (defined $updaterules) {
  # Iterate through the top-level trees under "firewall"
  foreach (keys %table_hash) {
    update_rules($_);
  }
  exit 0;
}

if ($#updateints == 4) {
  my ($action, $int_name, $direction, $chain, $tree) = @updateints;

  my ($table, $iptables_cmd) = (undef, undef);

  $tree = chain_configured(1, $chain, $tree);

  if (defined($tree)) {
    $table = $table_hash{$tree};
    $iptables_cmd = $cmd_hash{$tree};
  }
  if ($action eq "update") {
    # make sure chain exists
    if (!defined($tree)) {
      # require chain to be configured in "firewall" first
      print STDERR 'Firewall config error: ' .
                   "Rule set \"$chain\" is not configured\n";
      exit 1;
    }

    # do update action.
    update_ints(@updateints, $table, $iptables_cmd);
  } else {
    # delete
    if (defined($tree)) {
      update_ints(@updateints, $table, $iptables_cmd);
    } else {
      # chain not configured. try all tables.
      foreach (keys %table_hash) {
        update_ints(@updateints, $table_hash{$_}, $cmd_hash{$_});
      }
    }
  }

  exit 0;
}

sub find_chain_rule {
  my ($iptables_cmd, $table, $chain, $search) = @_;
  
  my ($num, $chain2) = (undef, undef);
  my @lines = `$iptables_cmd -t $table -L $chain -vn --line | egrep ^[0-9]`;
  if (scalar(@lines) < 1) {
    system("$logger DEBUG: find_chain_rule: @_ = none \n") if $syslog_flag;
    return;
  }
  foreach my $line (@lines) {
    ($num, undef, undef, $chain2) = split /\s+/, $line;
    last if $chain2 eq $search;
    ($num, $chain2) = (undef, undef);
  }

  if ($syslog_flag) {
    my $tmp_num = $num ? $num : -1;
    system("$logger DEBUG: find_chain_rule: @_ = $tmp_num");
  }

  return $num if defined $num;
  return;
}

if (defined $teardown) {
  foreach (keys %table_hash) {
    $update_zero_count += 1;
    teardown_iptables($table_hash{$_}, $cmd_hash{$_});
  }
  # remove the conntrack setup.
  foreach my $iptables_cmd ('iptables', 'ip6tables') {
    my $num;
    $num = find_chain_rule($iptables_cmd, 'raw', 'PREROUTING', 'FW_CONNTRACK');
    if (defined $num) {
      run_cmd("$iptables_cmd -t raw -D PREROUTING $num", 1, 1);
      run_cmd("$iptables_cmd -t raw -D OUTPUT $num", 1, 1);
      run_cmd("$iptables_cmd -t raw -F FW_CONNTRACK", 1, 1);
      run_cmd("$iptables_cmd -t raw -X FW_CONNTRACK", 1, 1);
    }
  }
  exit 0;
}

help();
exit 1;

sub help {
  print "usage: vyatta-firewall.pl\n";
  print "\t--setup              setup Vyatta specific iptables settings\n";
  print "\t--update-rules       update iptables with the current firewall rules\n";
  print "\t--update-interfaces  update the rules applpied to interfaces\n";
  print "\t                     (<action> <interface> <direction> <chain name>)\n";
  print "\t--teardown           teardown all user rules and iptables settings\n";
  print "\n";
}

sub run_cmd {
  my ($cmd_to_run, $redirect_flag, $logger_flag) = @_;

  my $cmd_extras = '';
  
  print "DEBUG: Running: $cmd_to_run \n" if $debug_flag;
  
  system("$logger DEBUG: Running: $cmd_to_run") if $syslog_flag;
  
  $cmd_extras  = ' 2>&1' if $redirect_flag;
  $cmd_extras .= " | $logger" if $logger_flag;
  
  system("$cmd_to_run $cmd_extras");
}

sub log_msg {
  my $message = shift;

  print "DEBUG: $message" if $debug_flag;

  system("$logger DEBUG: \"$message\"") if $syslog_flag;
}

sub update_rules {
  my $tree = shift;			# name, modify, ipv6-name or ipv6-modify
  my $table = $table_hash{$tree};	# "filter" or "mangle"
  my $iptables_cmd = $cmd_hash{$tree};  # "iptables" or "ip6tables"
  my $config = new Vyatta::Config;
  my $name = undef;
  my %nodes = ();

  log_msg "update_rules: $tree $table $iptables_cmd\n";

  $config->setLevel("firewall $tree");

  %nodes = $config->listNodeStatus();
  if ((scalar (keys %nodes)) == 0) {

    log_msg "update_rules: no nodes at this level \n";

    # no names. teardown the user chains and return.
    $update_zero_count += 1;
    teardown_iptables($table, $iptables_cmd);
    return;
  }
  
  # by default, nothing needs to be tracked.
  my $stateful = 0;

  # Iterate through ruleset names under "name" or "modify" 
  for my $name (keys %nodes) { 
    $config->setLevel("firewall $tree $name");
    my $policy = $config->returnValue("default-policy");
    $policy = 'drop' if ! defined $policy;
    my $old_policy = $config->returnOrigValue("default-policy");
    log_msg "update_rules: status of node $name is $nodes{$name} [$policy]\n";

    if ($nodes{$name} eq "static") {
      # not changed. check if stateful.
      $config->setLevel("firewall $tree $name rule");
      my @rules = $config->listOrigNodes();
      foreach (sort numerically @rules) {
	my $node = new Vyatta::IpTables::Rule;
        $node->setupOrig("firewall $tree $name rule $_");
        $node->set_ip_version($ip_version_hash{$tree});
        if ($node->is_stateful()) {
          $stateful = 1;
          last;
        }
      }
      next;
    } elsif ($nodes{$name} eq "added") {

      # create the chain
      my $ctree = chain_configured(2, $name, $tree);
      if (defined($ctree)) {
        # chain name must be unique in both trees
        printf STDERR 'Firewall config error: '
                     . "Rule set name \"$name\" already used in \"$ctree\"\n";
        exit 1;
      }
      setup_chain($table, "$name", $iptables_cmd, $policy);
      # handle the rules below.
    } elsif ($nodes{$name} eq "deleted") {

      log_msg "node $name is $nodes{$name} \n";

      # delete the chain
      if (chain_referenced($table, $name, $iptables_cmd)) {
        # disallow deleting a chain if it's still referenced
        print STDERR 'Firewall config error: '
                     . "Cannot delete rule set \"$name\" (still in use)\n";
        exit 1;
      }
      delete_chain($table, "$name", $iptables_cmd);
      next;
    } elsif ($nodes{$name} eq "changed") {
      # handle the rules below.
    }

    # set our config level to rule and get the rule numbers 
    $config->setLevel("firewall $tree $name rule");

    # Let's find the status of the rule nodes
    my %rulehash = ();
    %rulehash = $config->listNodeStatus();
    if ((scalar (keys %rulehash)) == 0) {
      # no rules. flush the user rules.
      # note that this clears the counters on the default DROP rule.
      # we could delete rule one by one if those are important.
      run_cmd("$iptables_cmd -t $table -F $name", 1, 1);
      next;
    }

    my $iptablesrule = 1;
    foreach my $rule (sort numerically keys %rulehash) {
      if ("$rulehash{$rule}" eq "static") {
	my $node = new Vyatta::IpTables::Rule;
        $node->setupOrig("firewall $tree $name rule $rule");
        $node->set_ip_version($ip_version_hash{$tree});
        if ($node->is_stateful()) {
          $stateful = 1;
        }
        my $ipt_rules = $node->get_num_ipt_rules();
	$iptablesrule += $ipt_rules;
      } elsif ("$rulehash{$rule}" eq "added") {
	# create a new iptables object of the current rule
	my $node = new Vyatta::IpTables::Rule;
	$node->setup("firewall $tree $name rule $rule");
        $node->set_ip_version($ip_version_hash{$tree});
        if ($node->is_stateful()) {
          $stateful = 1;
        }

        my ($err_str, @rule_strs) = $node->rule();
        if (defined($err_str)) {
          print STDERR "Firewall config error: $err_str\n";
          exit 1;
        }
        foreach (@rule_strs) {
          if (!defined) {
            last;
          }
          
          run_cmd("$iptables_cmd -t $table --insert $name $iptablesrule $_", 
                  0, 0);
          die "$iptables_cmd error: $! - $_" if ($? >> 8);
          $iptablesrule++;
        }
      } elsif ("$rulehash{$rule}" eq "changed") {
        # create a new iptables object of the current rule
        my $oldnode = new Vyatta::IpTables::Rule;
        $oldnode->setupOrig("firewall $tree $name rule $rule");
        $oldnode->set_ip_version($ip_version_hash{$tree});
        my $node = new Vyatta::IpTables::Rule;
        $node->setup("firewall $tree $name rule $rule");
        $node->set_ip_version($ip_version_hash{$tree});
        if ($node->is_stateful()) {
          $stateful = 1;
        }

        my ($err_str, @rule_strs) = $node->rule();
        if (defined($err_str)) {
          print STDERR "Firewall config error: $err_str\n";
          exit 1;
        }

        my $ipt_rules = $oldnode->get_num_ipt_rules();
        for (1 .. $ipt_rules) {
          run_cmd("$iptables_cmd -t $table --delete $name $iptablesrule", 0,
                  0);
          die "$iptables_cmd error: $! - $rule" if ($? >> 8);
        }
       
        foreach (@rule_strs) {
          if (!defined) {
            last;
          }
          run_cmd("$iptables_cmd -t $table --insert $name $iptablesrule $_", 
                  0, 0);
          die "$iptables_cmd error: $! - " , join(' ', @rule_strs) if ($? >> 8);
          $iptablesrule++;
        }
      } elsif ("$rulehash{$rule}" eq "deleted") {
	my $node = new Vyatta::IpTables::Rule;
        $node->setupOrig("firewall $tree $name rule $rule");
        $node->set_ip_version($ip_version_hash{$tree});

        my $ipt_rules = $node->get_num_ipt_rules();
        for (1 .. $ipt_rules) {
          run_cmd("$iptables_cmd -t $table --delete $name $iptablesrule", 
                  0, 0);
          die "$iptables_cmd error: $! - $rule" if ($? >> 8);
        }
      }
    } # foreach rule
    
    if (defined $old_policy and $policy ne $old_policy) {
      change_default_policy($table, $name, $iptables_cmd, $policy);
    }
  } # foreach name

  if ($stateful) {
    enable_fw_conntrack($iptables_cmd);
  } else {
    disable_fw_conntrack($iptables_cmd);
  }
}

# returns the "tree" in which the chain is configured; undef if not configured.
# mode: 0: check if the chain is configured in any tree.
#       1: check if it is configured in the specified tree.
#       2: check if it is configured in any "other" tree.
sub chain_configured {
  my ($mode, $chain, $tree) = @_;
  
  my $config = new Vyatta::Config;
  my %chains = ();
  foreach (keys %table_hash) {
    next if ($mode == 1 && $_ ne $tree);
    next if ($mode == 2 && $_ eq $tree);
 
    $config->setLevel("firewall $_");
    %chains = $config->listNodeStatus();

    if (grep(/^$chain$/, (keys %chains))) {
      if ($chains{$chain} ne "deleted") {
        return $_;
      }
    }
  }
  return; # undef
}

sub update_ints {
  my ($action, $int_name, $direction, $chain, $tree, $table, $iptables_cmd) = @_;
  my $interface = undef;
 
  log_msg "update_ints: @_ \n";

  if (! defined $action || ! defined $int_name || ! defined $direction
      || ! defined $chain || ! defined $table || ! defined $iptables_cmd) {
    return -1;
  }

  if ($action ne 'delete' && $table eq 'mangle' && $direction =~ /^local/) {
    print STDERR 'Firewall config error: ' .
                 "\"Modify\" rule set \"$chain\" cannot be used for " .
                 "\"local\"\n";
    exit 1;
  }

  $_ = $direction;
  my $dir_str = $direction;

  CASE: {
    /^in/    && do {
             $direction = 'VYATTA_IN_HOOK';
             $interface = "--in-interface $int_name";
             last CASE;
             };

    /^out/   && do {   
             $direction = 'VYATTA_OUT_HOOK';
             $interface = "--out-interface $int_name";
             last CASE;
             };

    /^local/ && do {
             # mangle disallowed above
             $direction = "INPUT";
             $interface = "--in-interface $int_name";
             last CASE;
             };
    }

  # In the update case, we want to see if the new rule will replace one
  # that is already in the table.  In the delete case, we need to find
  # the rule in the table that we need to delete.  Either way, we
  # start by listing the rules rules already in the table.
  my $grep = "egrep ^[0-9] | grep $int_name";
  my @lines
    = `$iptables_cmd -t $table -L $direction -n -v --line-numbers | $grep`;
  my ($cmd, $num, $oldchain, $in, $out, $ignore)
    = (undef, undef, undef, undef, undef, undef);

  foreach (@lines) {
    # Parse the line representing one rule in the table.  Note that
    # there is a slight difference in output format between the "iptables"
    # and "ip6tables" comands.  The "iptables" command displays "--" in
    # the "opt" column, while the "ip6tables" command leaves that
    # column blank.
    if ($iptables_cmd eq "iptables") {
      ($num, $ignore, $ignore, $oldchain, $ignore, $ignore, $in, $out,
       $ignore, $ignore) = split /\s+/;
    } else {
      ($num, $ignore, $ignore, $oldchain, $ignore,  $in, $out,
       $ignore, $ignore) = split /\s+/;
    }

    # Look for a matching rule...
    if (($dir_str eq 'in' && $in eq $int_name) 
        || ($dir_str eq 'out' && $out eq $int_name)
        || ($dir_str eq 'local' && $in eq $int_name)) {
      # found a matching rule
      if ($action eq 'update') {
        # replace old rule
        $action = 'replace';
        $cmd = "--replace $direction $num $interface --jump $chain";
      } else {
        # delete old rule
        $cmd = "--delete $direction $num";
      }
      last;
    }
  }

  if (!defined($cmd)) {
    # no matching rule
    if ($action eq 'update') {
      # add new rule.
      # there is a post-fw rule at the end. insert at the front.      
      $cmd = "--insert $direction 1 $interface --jump $chain";
    } else {
      # delete non-existent rule!
      # not an error. rule may be in the other table.
    }
  }

  # no match. do nothing.
  return 0 if (!defined($cmd));

  run_cmd("$iptables_cmd -t $table $cmd", 0, 0);
  exit 1 if ($? >> 8);
 
  # the following delete_chain is probably no longer necessary since we
  # now disallow deleting a chain when it's still referenced
  if ($action eq 'replace' || $action eq 'delete') {
    if (!defined(chain_configured(1, $oldchain, $tree))) {
      if (!chain_referenced($table, $oldchain, $iptables_cmd)) {
        delete_chain($table, $oldchain, $iptables_cmd);
      }
    }
  }
  return 0;
}

sub enable_fw_conntrack {
  # potentially we can add rules in the FW_CONNTRACK chain to provide
  # finer-grained control over which packets are tracked.
  my $iptables_cmd = shift;
  log_msg("enable_fw_conntrack($iptables_cmd)");
  run_cmd("$iptables_cmd -t raw -R FW_CONNTRACK 1 -j ACCEPT", 1, 1);
}

sub disable_fw_conntrack {
  my $iptables_cmd = shift;
  log_msg("disable_fw_conntrack\($iptables_cmd\)");
  run_cmd("$iptables_cmd -t raw -R FW_CONNTRACK 1 -j RETURN", 1, 1);
}


sub teardown_iptables {
  my ($table, $iptables_cmd) = @_;
  log_msg "teardown_iptables executing: $iptables_cmd -L -n -t $table\n";
  my @chains = `$iptables_cmd -L -n -t $table`;
  my $chain;

  # $chain is going to look like this...
  # Chain inbound (0 references)
  foreach my $chain (@chains) {
    # chains start with Chain 
    if ($chain =~ s/^Chain//) {
      # make sure this is a user chain by looking at "references".
      # make sure this is not a hook.
      if (($chain =~ /references/) && !($chain =~ /VYATTA_\w+_HOOK/)) {
	($chain) = split /\(/, $chain;
        $chain =~ s/\s//g;
        delete_chain($table, "$chain", $iptables_cmd);
      }
    }
  }

  # remove VYATTA_(IN|OUT)_HOOK
  my $ihook = $inhook_hash{$table};
  my $num = find_chain_rule($iptables_cmd, $table, $ihook, 'VYATTA_IN_HOOK');
  if (defined $num) {
    run_cmd("$iptables_cmd -t $table -D $ihook $num", 1, 1);
    run_cmd("$iptables_cmd -t $table -F VYATTA_IN_HOOK", 1, 1);
    run_cmd("$iptables_cmd -t $table -X VYATTA_IN_HOOK", 1, 1);
  }
  my $ohook = $outhook_hash{$table};
  $num = find_chain_rule($iptables_cmd, $table, $ohook, 'VYATTA_OUT_HOOK');
  if (defined $num) {
    run_cmd("$iptables_cmd -t $table -D $ohook $num", 1, 1);
    run_cmd("$iptables_cmd -t $table -F VYATTA_OUT_HOOK", 1, 1);
    run_cmd("$iptables_cmd -t $table -X VYATTA_OUT_HOOK", 1, 1);
  }
}

sub setup_iptables {
  my $iptables_cmd = shift;
  log_msg "setup_iptables [$iptables_cmd]\n";
  foreach my $table (qw(filter mangle)) {
    $update_zero_count += 1;
    teardown_iptables($table, $iptables_cmd);
    my $ihook = $inhook_hash{$table};
    my $ohook = $outhook_hash{$table};
    # add VYATTA_(IN|OUT)_HOOK
    run_cmd("$iptables_cmd -t $table -N VYATTA_OUT_HOOK", 1, 1);
    run_cmd("$iptables_cmd -t $table -N VYATTA_IN_HOOK", 1, 1);
    run_cmd("$iptables_cmd -t $table -I $ohook 1 -j VYATTA_OUT_HOOK", 1, 1);
    run_cmd("$iptables_cmd -t $table -I $ihook 1 -j VYATTA_IN_HOOK", 1, 1);
  }

  # by default, nothing is tracked (the last rule in raw/PREROUTING).
  run_cmd("$iptables_cmd -t raw -N FW_CONNTRACK", 1 , 1);
  run_cmd("$iptables_cmd -t raw -A FW_CONNTRACK -j RETURN", 1, 1);
  run_cmd("$iptables_cmd -t raw -I PREROUTING 1 -j FW_CONNTRACK", 1, 1);
  run_cmd("$iptables_cmd -t raw -I OUTPUT 1 -j FW_CONNTRACK", 1, 1);

  return 0;
}

sub add_default_drop_rule {
  my ($table, $chain, $iptables_cmd) = @_;
  log_msg("add_default_drop_rule($iptables_cmd, $table, $chain)");
  my $comment = "-m comment --comment \"$chain-1025\"";
  run_cmd("$iptables_cmd -t $table -A $chain $comment -j DROP", 1, 1);
}

sub set_default_policy {
  my ($table, $chain, $iptables_cmd, $policy) = @_;

  $policy = 'drop' if ! defined $policy;
  log_msg("set_default_policy($iptables_cmd, $table, $chain, $policy)");
  my $target = $policy_hash{$policy};
  my $comment = "-m comment --comment \"$chain-1025 default-policy $policy\"";
  run_cmd("$iptables_cmd -t $table -A $chain $comment -j $target", 1, 1);
}

sub count_iptables_rules {
  my ($table, $chain, $iptables_cmd) = @_;
  my @lines = `$iptables_cmd -t $table -L $chain -n --line`;
  my $cnt = 0;
  foreach my $line (@lines) {
    $cnt++ if $line =~ /^\d/;
  }
  return $cnt;
}

sub change_default_policy {
  my ($table, $chain, $iptables_cmd, $policy) = @_;
  
  $policy = 'drop' if ! defined $policy;
  log_msg("change_default_policy($iptables_cmd, $table, $chain, $policy)");
  my $target = $policy_hash{$policy};
  my $comment = "-m comment --comment \"$chain-1025 default-policy $policy\"";
  my $default_rule = count_iptables_rules($table, $chain, $iptables_cmd);
  run_cmd("$iptables_cmd -t $table -A $chain $comment -j $target", 1, 1);
  run_cmd("$iptables_cmd -t $table -D $chain $default_rule", 1, 1);
}

sub setup_chain {
  my ($table, $chain, $iptables_cmd, $policy) = @_;

  my $configured = `$iptables_cmd -t $table -n -L $chain 2>&1 | head -1`;

  $_ = $configured;
  if (!/^Chain $chain/) {
    run_cmd("$iptables_cmd -t $table --new-chain $chain", 0, 0);
    die "iptables error: $table $chain --new-chain: $!" if ($? >> 8);
    set_default_policy($table, $chain, $iptables_cmd, $policy);
  }
}

sub chain_referenced {
  my ($table, $chain, $iptables_cmd) = @_;

  log_msg "chain_referenced executing: $iptables_cmd -t $table -n -L $chain \n";

  my $line = `$iptables_cmd -t $table -n -L $chain 2>/dev/null |head -n1`;
  if ($line =~ m/^Chain $chain \((\d+) references\)$/) {
    if ($1 > 0) {
      return 1;
    }
  }
  return 0;
}

sub delete_chain {
  my ($table, $chain, $iptables_cmd) = @_;
  
  log_msg "delete_chain executing: $iptables_cmd -t $table -n -L $chain \n";

  my $configured = `$iptables_cmd -t $table -n -L $chain 2>&1 | head -1`;

  if ($configured =~ /^Chain $chain/) {
    run_cmd("$iptables_cmd -t $table --flush $chain", 0, 0);
    die "$iptables_cmd error: $table $chain --flush: $!" if ($? >> 8);
    if (!chain_referenced($table, $chain, $iptables_cmd)) {
      run_cmd("$iptables_cmd -t $table --delete-chain $chain", 0, 0);
      die "$iptables_cmd error: $table $chain --delete-chain: $!" if ($? >> 8);
    } else {
      add_default_drop_rule($table, $chain, $iptables_cmd);
    }
  }
}

sub numerically { $a <=> $b; }

# Local Variables:
# mode: perl
# indent-tabs-mode: nil
# perl-indent-level: 2
# End:
