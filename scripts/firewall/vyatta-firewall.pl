#!/usr/bin/perl

use lib "/opt/vyatta/share/perl5/";
use VyattaConfig;
use VyattaIpTablesRule;
use VyattaIpTablesAddressFilter;
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

if (defined $setup) {
  setup_iptables();
  exit 0;
}

if (defined $updaterules) {
  update_rules();
  exit 0;
}

if ($#updateints == 3) {
  update_ints(@updateints);
  exit 0;
}

if (defined $teardown) {
  teardown_iptables();
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

sub update_rules() {
  my $config = new VyattaConfig;
  my $name = undef;
  my %nodes = ();

  system ("$logger Executing update_rules.");

  $config->setLevel("firewall name");

  %nodes = $config->listNodeStatus();
  if ((scalar (keys %nodes)) == 0) {
    # no names. teardown the user chains and return.
    teardown_iptables();
    return;
  }
  
  # by default, nothing needs to be tracked.
  my $stateful = 0;

  for $name (keys %nodes) { 
    if ($nodes{$name} eq "static") {
      # not changed. check if stateful.
      $config->setLevel("firewall name $name rule");
      my @rules = $config->listOrigNodes();
      foreach (sort numerically @rules) {
	my $node = new VyattaIpTablesRule;
        $node->setupOrig("firewall name $name rule $_");
        if ($node->is_stateful()) {
          $stateful = 1;
          last;
        }
      }
      next;
    } elsif ($nodes{$name} eq "added") {
      # create the chain
      setup_chain("$name");
      # handle the rules below.
    } elsif ($nodes{$name} eq "deleted") {
      # delete the chain
      delete_chain("$name");
      next;
    } elsif ($nodes{$name} eq "changed") {
      # handle the rules below.
    }

    # set our config level to rule and get the rule numbers 
    $config->setLevel("firewall name $name rule");

    # Let's find the status of the rule nodes
    my %rulehash = ();
    %rulehash = $config->listNodeStatus();
    if ((scalar (keys %rulehash)) == 0) {
      # no rules. flush the user rules.
      # note that this clears the counters on the default DROP rule.
      # we could delete rule one by one if those are important.
      system("$logger Running: iptables -F $name");
      system("iptables -F $name 2>&1 | $logger");
      system("$logger Running: iptables -A $name -j DROP");
      system("iptables -A $name -j DROP 2>&1 | $logger");
      next;
    }

    my $iptablesrule = 1;
    foreach $rule (sort numerically keys %rulehash) {
      if ("$rulehash{$rule}" eq "static") {
	my $node = new VyattaIpTablesRule;
        $node->setupOrig("firewall name $name rule $rule");
        if ($node->is_stateful()) {
          $stateful = 1;
        }
        my $ipt_rules = $node->get_num_ipt_rules();
	$iptablesrule += $ipt_rules;
      } elsif ("$rulehash{$rule}" eq "added") {
	# create a new iptables object of the current rule
	my $node = new VyattaIpTablesRule;
	$node->setup("firewall name $name rule $rule");
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
	  system ("$logger Running: iptables --insert $name $iptablesrule $_");
          system ("iptables --insert $name $iptablesrule $_ 2>&1 | $logger") == 0
            || die "iptables error: $? - $_\n";
          $iptablesrule++;
        }
      } elsif ("$rulehash{$rule}" eq "changed") {
        # create a new iptables object of the current rule
        my $oldnode = new VyattaIpTablesRule;
        $oldnode->setupOrig("firewall name $name rule $rule");
        my $node = new VyattaIpTablesRule;
        $node->setup("firewall name $name rule $rule");
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
	  system ("$logger Running: iptables --delete $name $iptablesrule");
          system ("iptables --delete $name $iptablesrule 2>&1 | $logger") == 0
            || die "iptables error: $? - $rule\n";
        }
       
        foreach (@rule_strs) {
          if (!defined) {
            last;
          }
	  system ("$logger Running: iptables --insert $name $iptablesrule $_");
          system ("iptables --insert $name $iptablesrule $_ 2>&1 | $logger") == 0
            || die "iptables error: $? - $rule_str\n";
          $iptablesrule++;
        }
      } elsif ("$rulehash{$rule}" eq "deleted") {
	my $node = new VyattaIpTablesRule;
        $node->setupOrig("firewall name $name rule $rule");

        my $ipt_rules = $node->get_num_ipt_rules();
        for (1 .. $ipt_rules) {
	  system ("$logger Running: iptables --delete $name $iptablesrule");
          system ("iptables --delete $name $iptablesrule 2>&1 | $logger") == 0
            || die "iptables error: $? - $rule\n";
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

sub chain_configured($) {
  my $chain = shift;
  
  my $config = new VyattaConfig;
  my %chains = ();
  $config->setLevel("firewall name");
  %chains = $config->listNodeStatus();

  if (grep(/^$chain$/, (keys %chains))) {
    if ($chains{$chain} ne "deleted") {
      return 1;
    }
  }
  return 0;
}

sub update_ints() {
  my ($action, $int_name, $direction, $chain) = @_;
  my $interface = undef;
 
  if (! defined $action || ! defined $int_name || ! defined $direction || ! defined $chain) {
    return -1;
  }
 
  if ($action eq "update") {
    # make sure chain exists
    setup_chain($chain);
  }

  $_ = $direction;
  my $dir_str = $direction;

  CASE: {
    /^in/    && do {
             $direction = "FORWARD";
             $interface = "--in-interface $int_name";
             last CASE;
             };

    /^out/   && do {   
             $direction = "FORWARD";
             $interface = "--out-interface $int_name";
             last CASE;
             };

    /^local/ && do {
             $direction = "INPUT";
             $interface = "--in-interface $int_name";
             last CASE;
             };
    }

  my $grep = "| grep $int_name";
  my $line = `iptables -L $direction -n -v --line-numbers | egrep ^[0-9] $grep`;
  my ($num, $ignore, $ignore, $oldchain, $ignore, $ignore, $in, $out, $ignore, $ignore) = split /\s+/, $line;

  if ("$action" eq "update") {
    if (($num =~ /.+/) && (($dir_str eq "in" && $in eq $int_name)
                           || ($dir_str eq "out" && $out eq $int_name)
                           || ($dir_str eq "local"))) {
      $action = "replace";
      $rule = "--replace $direction $num $interface --jump $chain";
    } else {
      $rule = "--append $direction $interface --jump $chain";
    }
  }
  else {
    $rule = "--$action $direction $num";
  }   

  system ("$logger Running: iptables $rule");
  $ret = system("iptables $rule 2>&1 | $logger");
  if ($ret >> 8) {
    exit 1;
  }
  if ($action eq "replace" || $action eq "delete") {
    if (!chain_configured($oldchain)) {
      if (!chain_referenced($oldchain)) {
        delete_chain($oldchain);
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

sub teardown_iptables() {
  my @chains = `iptables -L -n`;
  my $chain;

  # $chain is going to look like this...
  # Chain inbound (0 references)
  foreach $chain (@chains) {
    # chains start with Chain 
    if ($chain =~ s/^Chain//) {
      # all we need to do is make sure this is a user chain
      # by looking at the references keyword and then
      if ($chain =~ /references/) {
	($chain) = split /\(/, $chain;
        $chain =~ s/\s//g;
        delete_chain("$chain");
      }
    }
  }
 
  # remove the conntrack setup.
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
  teardown_iptables();
  # by default, nothing is tracked (the last rule in raw/PREROUTING).
  system("iptables -t raw -N FW_CONNTRACK 2>&1 | $logger");
  system("iptables -t raw -A FW_CONNTRACK -j RETURN 2>&1 | $logger");
  system("iptables -t raw -I PREROUTING 1 -j FW_CONNTRACK 2>&1 | $logger");
  system("iptables -t raw -I OUTPUT 1 -j FW_CONNTRACK 2>&1 | $logger");
  return 0;
}

sub setup_chain($) {
  my $chain = shift;
  my $configured = `iptables -n -L $chain 2>&1 | head -1`;

  $_ = $configured;
  if (!/^Chain $chain/) {
    system("iptables --new-chain $chain 2>&1 | $logger") == 0 || die "iptables error: $chain --new-chain: $?\n";
    system("iptables -A $chain -j DROP 2>&1 | $logger");
  }
}

sub chain_referenced($) {
  my $chain = shift;
  my $line = `iptables -n -L $chain |head -n1`;
  if ($line =~ m/^Chain $chain \((\d+) references\)$/) {
    if ($1 > 0) {
      return 1;
    }
  }
  return 0;
}

sub delete_chain($) {
  my $chain = shift;
  my $configured = `iptables -n -L $chain 2>&1 | head -1`;

  if ($configured =~ /^Chain $chain/) {
    system("iptables --flush $chain 2>&1 | $logger") == 0        || die "iptables error: $chain --flush: $?\n";
    if (!chain_referenced($chain)) {
      system("iptables --delete-chain $chain 2>&1 | $logger") == 0 || die "iptables error: $chain --delete-chain: $?\n";
    }
  }
}

sub numerically { $a <=> $b; }
