#!/usr/bin/perl

use lib "/opt/vyatta/share/perl5/";
use VyattaConfig;
use VyattaIpTablesRule;
use VyattaIpTablesAddressFilter;

exit 1 if ($#ARGV < 1);
my $chain_name = $ARGV[0];
my $xsl_file = $ARGV[1];
my $rule_num = $ARGV[2];    # rule number to match (optional)

sub numerically { $a <=> $b; }

sub show_chain {
  my $chain = shift;
  my $fh = shift;

  open(STATS, "iptables -L $chain -vn |") or exit 1;
  my @stats = ();
  while (<STATS>) {
    if (!/^\s*(\d+[KMG]?)\s+(\d+[KMG]?)\s/) {
      next;
    }
    push @stats, ($1, $2);
  }
  close STATS;

  print $fh "<opcommand name='firewallrules'><format type='row'>\n";
  my $config = new VyattaConfig;
  $config->setLevel("firewall name $chain rule");
  my @rules = sort numerically $config->listOrigNodes();
  foreach (@rules) {
    # just take the stats from the 1st iptables rule and remove unneeded stats
    # (if this rule corresponds to multiple iptables rules). note that
    # depending on how our rule is translated into multiple iptables rules,
    # this may actually need to be the sum of all corresponding iptables stats
    # instead of just taking the first pair.
    my $pkts = shift @stats;
    my $bytes = shift @stats;
    my $rule = new VyattaIpTablesRule;
    $rule->setupOrig("firewall name $chain rule $_");
    my $ipt_rules = $rule->get_num_ipt_rules();
    splice(@stats, 0, (($ipt_rules - 1) * 2));

    if (defined($rule_num) && $rule_num != $_) {
      next;
    }
    print $fh "  <row>\n";
    print $fh "    <rule_number>$_</rule_number>\n";
    print $fh "    <pkts>$pkts</pkts>\n";
    print $fh "    <bytes>$bytes</bytes>\n";
    $rule->outputXml($fh);
    print $fh "  </row>\n";
  }
  if (!defined($rule_num)) {
    # dummy rule
    print $fh "  <row>\n";
    print $fh "    <rule_number>1025</rule_number>\n";
    my $pkts = shift @stats;
    my $bytes = shift @stats;
    print $fh "    <pkts>$pkts</pkts>\n";
    print $fh "    <bytes>$bytes</bytes>\n";
    my $rule = new VyattaIpTablesRule;
    $rule->setupDummy();
    $rule->outputXml($fh);
    print $fh "  </row>\n";
  }
  print $fh "</format></opcommand>\n";
}

if ($chain_name eq "-all") {
  my $config = new VyattaConfig;
  $config->setLevel("firewall name");
  my @chains = $config->listOrigNodes();
  foreach (@chains) {
    print "Firewall \"$_\":\n";
    open(RENDER, "| /opt/vyatta/libexec/xorp/render_xml $xsl_file") or exit 1;
    show_chain($_, *RENDER{IO});
    close RENDER;
    print "-" x 80 . "\n";
  }
} else {
  open(RENDER, "| /opt/vyatta/libexec/xorp/render_xml $xsl_file") or exit 1;
  show_chain($chain_name, *RENDER{IO});
  close RENDER;
}

exit 0;

