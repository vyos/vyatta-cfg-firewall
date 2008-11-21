#!/usr/bin/perl

use lib "/opt/vyatta/share/perl5";
use VyattaConfig;
use Vyatta::IpTables::Rule;
use Vyatta::IpTables::AddressFilter;
use Getopt::Long;

# Send output of shell commands to syslog for debugging and so that
# the user is not confused by it.  Log at debug level, which is supressed
# by default, so that we don't unnecessarily fill up the syslog file.

my $logger = 'logger -t firewall-cfg -p local0.debug --';

my @updateints = ();
GetOptions("setup"             => \$setup, 
           "teardown"          => \$teardown,
 	   "update-rules"      => \$updaterules,
	   "update-interfaces=s{4}" => \@updateints,
);

# mapping from config node to iptables table
my %table_hash = ( 'name'   => 'filter',
                   'modify' => 'mangle', );

sub other_table {
  my $this = shift;
  return (($this eq 'filter') ? 'mangle' : 'filter');
}

if (defined $setup) {
  setup_iptables();
  exit 0;
}

my $update_zero_count = 0;
if (defined $updaterules) {
  foreach (keys %table_hash) {
    update_rules($_);
  }
  exit 0;
}

if ($#updateints == 3) {
  my ($action, $int_name, $direction, $chain) = @updateints;
  my $tree = chain_configured(0, $chain, undef);
  my $table = $table_hash{$tree};
  if ($action eq "update") {
    # make sure chain exists
    if (!defined($tree)) {
      # require chain to be configured in "firewall" first
      print STDERR 'Firewall config error: ' .
                   "Rule set \"$chain\" is not configured\n";
      exit 1;
    }
    # chain must have been set up. no need to set up again.
    # user may specify a chain in a different tree. try to delete it
    # from the "other" tree first.
    update_ints('delete', $int_name, $direction, $chain, other_table($table));
    # do update action.
    update_ints(@updateints, $table);
  } else {
    # delete
    if (defined($tree)) {
      update_ints(@updateints, $table);
    } else {
      # chain not configured. try both tables.
      foreach (keys %table_hash) {
        update_ints(@updateints, $table_hash{$_});
      }
    }
  }

  exit 0;
}

if (defined $teardown) {
  foreach (keys %table_hash) {
    $update_zero_count += 1;
    teardown_iptables($table_hash{$_});
  }
  exit 0;
}

help();
exit 1;

sub help() {
  print "usage: vyatta-firewall.pl\n";
  print "\t--setup              setup Vyatta specific iptables settings\n";
  print "\t--update-rules       update iptables with the current firewall rules\n";
  print "\t--update-interfaces  update the rules applpied to interfaces\n";
  print "\t                     (<action> <interface> <direction> <chain name>)\n";
  print "\t--teardown           teardown all user rules and iptables settings\n";
  print "\n";
}

sub update_rules($) {
  my $tree = shift;
  my $table = $table_hash{$tree};
  my $config = new VyattaConfig;
  my $name = undef;
  my %nodes = ();

  system ("$logger Executing update_rules.");

  $config->setLevel("firewall $tree");

  %nodes = $config->listNodeStatus();
  if ((scalar (keys %nodes)) == 0) {
    # no names. teardown the user chains and return.
    $update_zero_count += 1;
    teardown_iptables($table);
    return;
  }
  
  # by default, nothing needs to be tracked.
  my $stateful = 0;

  for $name (keys %nodes) { 
    if ($nodes{$name} eq "static") {
      # not changed. check if stateful.
      $config->setLevel("firewall $tree $name rule");
      my @rules = $config->listOrigNodes();
      foreach (sort numerically @rules) {
	my $node = new VyattaIpTablesRule;
        $node->setupOrig("firewall $tree $name rule $_");
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
        print STDERR 'Firewall config error: '
                     . "Rule set name \"$name\" already used in \"$ctree\"\n";
        exit 1;
      }
      setup_chain($table, "$name");
      # handle the rules below.
    } elsif ($nodes{$name} eq "deleted") {
      # delete the chain
      if (chain_referenced($table, $name)) {
        # disallow deleting a chain if it's still referenced
        print STDERR 'Firewall config error: '
                     . "Cannot delete rule set \"$name\" (still in use)\n";
        exit 1;
      }
      delete_chain($table, "$name");
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
      system("$logger Running: iptables -F $name");
      system("iptables -t $table -F $name 2>&1 | $logger");
      add_default_drop_rule($table, $name);
      next;
    }

    my $iptablesrule = 1;
    foreach $rule (sort numerically keys %rulehash) {
      if ("$rulehash{$rule}" eq "static") {
	my $node = new VyattaIpTablesRule;
        $node->setupOrig("firewall $tree $name rule $rule");
        if ($node->is_stateful()) {
          $stateful = 1;
        }
        my $ipt_rules = $node->get_num_ipt_rules();
	$iptablesrule += $ipt_rules;
      } elsif ("$rulehash{$rule}" eq "added") {
	# create a new iptables object of the current rule
	my $node = new VyattaIpTablesRule;
	$node->setup("firewall $tree $name rule $rule");
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
	  system ("$logger Insert iptables $table $name $iptablesrule $_");
          system ("iptables -t $table --insert $name $iptablesrule $_");
          die "iptables error: $! - $_" if ($? >> 8);
          $iptablesrule++;
        }
      } elsif ("$rulehash{$rule}" eq "changed") {
        # create a new iptables object of the current rule
        my $oldnode = new VyattaIpTablesRule;
        $oldnode->setupOrig("firewall $tree $name rule $rule");
        my $node = new VyattaIpTablesRule;
        $node->setup("firewall $tree $name rule $rule");
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
	  system ("$logger Delete iptables $table $name $iptablesrule");
          system ("iptables -t $table --delete $name $iptablesrule");
          die "iptables error: $! - $rule" if ($? >> 8);
        }
       
        foreach (@rule_strs) {
          if (!defined) {
            last;
          }
	  system ("$logger Insert iptables $table $name $iptablesrule $_");
          system ("iptables -t $table --insert $name $iptablesrule $_");
          die "iptables error: $! - $rule_str" if ($? >> 8);
          $iptablesrule++;
        }
      } elsif ("$rulehash{$rule}" eq "deleted") {
	my $node = new VyattaIpTablesRule;
        $node->setupOrig("firewall $tree $name rule $rule");

        my $ipt_rules = $node->get_num_ipt_rules();
        for (1 .. $ipt_rules) {
	  system ("$logger Delete iptables $table $name $iptablesrule");
          system ("iptables -t $table --delete $name $iptablesrule");
          die "iptables error: $! - $rule" if ($? >> 8);
        }
      }
    }
  }
  if ($stateful) {
    enable_fw_conntrack();
  } else {
    disable_fw_conntrack();
  }
}

# returns the "tree" in which the chain is configured; undef if not configured.
# mode: 0: check if the chain is configured in either tree.
#       1: check if it is configured in the specified tree.
#       2: check if it is configured in the "other" tree.
sub chain_configured($$$) {
  my ($mode, $chain, $tree) = @_;
  
  my $config = new VyattaConfig;
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
  return undef;
}

sub update_ints() {
  my ($action, $int_name, $direction, $chain, $table) = @_;
  my $interface = undef;
 
  if (! defined $action || ! defined $int_name || ! defined $direction
      || ! defined $chain || ! defined $table) {
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
             $direction = ($table eq 'mangle') ? 'PREROUTING' : 'FORWARD';
             $interface = "--in-interface $int_name";
             last CASE;
             };

    /^out/   && do {   
             $direction = ($table eq 'mangle') ? 'POSTROUTING' : 'FORWARD';
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

  my $grep = "egrep ^[0-9] | grep $int_name";
  my @lines
    = `iptables -t $table -L $direction -n -v --line-numbers | $grep`;
  my ($cmd, $num, $oldchain, $in, $out, $ignore)
    = (undef, undef, undef, undef, undef, undef);
  foreach (@lines) {
    ($num, $ignore, $ignore, $oldchain, $ignore, $ignore, $in, $out,
     $ignore, $ignore) = split /\s+/;
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

  system ("$logger Running: iptables -t $table $cmd");
  system("iptables -t $table $cmd");
  exit 1 if ($? >> 8);
 
  # the following delete_chain is probably no longer necessary since we
  # now disallow deleting a chain when it's still referenced
  if ($action eq 'replace' || $action eq 'delete') {
    if (!defined(chain_configured(2, $oldchain, undef))) {
      if (!chain_referenced($table, $oldchain)) {
        delete_chain($table, $oldchain);
      }
    }
  }
  return 0;
}

sub enable_fw_conntrack {
  # potentially we can add rules in the FW_CONNTRACK chain to provide
  # finer-grained control over which packets are tracked.
  system("$logger Running: iptables -t raw -R FW_CONNTRACK 1 -J ACCEPT");
  system("iptables -t raw -R FW_CONNTRACK 1 -j ACCEPT 2>&1 | $logger");
}

sub disable_fw_conntrack {
  system("$logger Running: iptables -t raw -R FW_CONNTRACK 1 -j RETURN");
  system("iptables -t raw -R FW_CONNTRACK 1 -j RETURN 2>&1 | $logger");
}

sub teardown_iptables($) {
  my $table = shift;
  my @chains = `iptables -L -n -t $table`;
  my $chain;

  # $chain is going to look like this...
  # Chain inbound (0 references)
  foreach $chain (@chains) {
    # chains start with Chain 
    if ($chain =~ s/^Chain//) {
      # make sure this is a user chain by looking at "references".
      # make sure this is not a hook.
      if (($chain =~ /references/) && !($chain =~ /VYATTA_\w+_HOOK/)) {
	($chain) = split /\(/, $chain;
        $chain =~ s/\s//g;
        delete_chain($table, "$chain");
      }
    }
  }
 
  # remove the conntrack setup.
  return if ($update_zero_count != scalar(keys %table_hash));
  my @lines
    = `iptables -t raw -L PREROUTING -vn --line-numbers | egrep ^[0-9]`;
  foreach (@lines) {
    my ($num, $ignore, $ignore, $chain, $ignore, $ignore, $in, $out,
        $ignore, $ignore) = split /\s+/;
    if ($chain eq "FW_CONNTRACK") {
      system("iptables -t raw -D PREROUTING $num 2>&1 | $logger");
      system("iptables -t raw -D OUTPUT $num 2>&1 | $logger");
      system("iptables -t raw -F FW_CONNTRACK 2>&1 | $logger");
      system("iptables -t raw -X FW_CONNTRACK 2>&1 | $logger");
      last;
    }
  }
}

sub setup_iptables() {
  foreach (keys %table_hash) {
    $update_zero_count += 1;
    teardown_iptables($table_hash{$_});
  }
  # by default, nothing is tracked (the last rule in raw/PREROUTING).
  system("iptables -t raw -N FW_CONNTRACK 2>&1 | $logger");
  system("iptables -t raw -A FW_CONNTRACK -j RETURN 2>&1 | $logger");
  system("iptables -t raw -I PREROUTING 1 -j FW_CONNTRACK 2>&1 | $logger");
  system("iptables -t raw -I OUTPUT 1 -j FW_CONNTRACK 2>&1 | $logger");
  return 0;
}

sub add_default_drop_rule($$) {
  my ($table, $chain) = @_;
  system("iptables -t $table -A $chain -j DROP 2>&1 | $logger");
}

sub setup_chain($$) {
  my ($table, $chain) = @_;
  my $configured = `iptables -t $table -n -L $chain 2>&1 | head -1`;

  $_ = $configured;
  if (!/^Chain $chain/) {
    system("iptables -t $table --new-chain $chain");
    die "iptables error: $table $chain --new-chain: $!" if ($? >> 8);
    add_default_drop_rule($table, $chain);
  }
}

sub chain_referenced($$) {
  my ($table, $chain) = @_;
  my $line = `iptables -t $table -n -L $chain 2>/dev/null |head -n1`;
  if ($line =~ m/^Chain $chain \((\d+) references\)$/) {
    if ($1 > 0) {
      return 1;
    }
  }
  return 0;
}

sub delete_chain($$) {
  my ($table, $chain) = @_;
  my $configured = `iptables -t $table -n -L $chain 2>&1 | head -1`;

  if ($configured =~ /^Chain $chain/) {
    system("iptables -t $table --flush $chain");
    die "iptables error: $table $chain --flush: $!" if ($? >> 8);
    if (!chain_referenced($table, $chain)) {
      system("iptables -t $table --delete-chain $chain");
      die "iptables error: $table $chain --delete-chain: $!" if ($? >> 8);
    } else {
      add_default_drop_rule($table, $chain);
    }
  }
}

sub numerically { $a <=> $b; }
