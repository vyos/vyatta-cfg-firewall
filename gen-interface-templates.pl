#!/usr/bin/perl

my $debug = 0;

my %interface_hash = ( 
    'adsl/node.tag/pvc/node.tag/bridged-ethernet' => 
	'adsl$VAR(../../../../../@)', 
    'adsl/node.tag/pvc/node.tag/classical_ipoa' =>
	'adsl$VAR(../../../../../@)', 
    'adsl/node.tag/pvc/node.tag/pppoa/node.tag' => 'pppoa$VAR(../../../@)',
    'adsl/node.tag/pvc/node.tag/pppoe/node.tag' => 'pppoe$VAR(../../../@)',

    'bonding/node.tag' => '$VAR(../../../@)',
    'bonding/node.tag/vif/node.tag' => 
	'$VAR(../../../../@).$VAR(../../../../@)',

    'ethernet/node.tag' => '$VAR(../../../@)',
    'ethernet/node.tag/pppoe/node.tag' => 'pppoe$VAR(../../../@)',
    'ethernet/node.tag/vif/node.tag' =>
	'$VAR(../../../../@).$VAR(../../../../@)',
    'ethernet/node.tag/vif/node.tag/pppoe/node.tag' => 
	'pppoe$VAR(../../../@)',

    'tunnel/node.tag'  => '$VAR(../../../@)',
);    

my $template_subdir="generated-templates/interfaces";
my $firewall_subdir="firewall";
my $node_file="node.def";

sub gen_firewall_template {
    my ($if_tree) = @_;

    system ("mkdir -p ${template_subdir}/${if_tree}/${firewall_subdir}");

    open (TP, ">${template_subdir}/${if_tree}/${firewall_subdir}/${node_file}");

    my $date=`date`;
    print TP "# Template generated at: $date";
    print TP "\n";
    print TP "help: Set firewall options\n";
    close(TP);
}


my %direction_help_hash = (
    "in" => "forwarded packets on inbound interface",
    "out" => "forwarded packets on outbound interface",
    "local" => "packets destined for this router",
    );


sub gen_direction_template {
    my ($if_tree, $direction) = @_;

    system ("mkdir -p ${template_subdir}/${if_tree}/${firewall_subdir}/${direction}");

    open (TP, ">${template_subdir}/${if_tree}/${firewall_subdir}/${direction}/${node_file}");

    my $date=`date`;
    print TP "# Template generated at: $date";
    print TP "\n";
    print TP "help: Set ruleset for $direction_help_hash{$direction}\n";
    close(TP);
}

my %direction_term_hash = (
    "in" => "inbound",
    "out" => "outbound",
    "local" => "local",
    );

my %table_help_hash = (
    "name" => "IPv4 firewall",
    "ipv6-name" => "IPv6 firewall",
    "modify" => "IPv4 modify",
    "ipv6-modify" => "IPv6 modify",
    );


sub gen_template {
    my ($if_tree, $direction, $table, $if_name) = @_;

    if ($debug) {
	print "debug: table=$table direction=$direction\n";
    }

    my $template_dir="${template_subdir}/${if_tree}/${firewall_subdir}/${direction}/${table}";

    if ($debug) {
	print "debug: template_dir=$template_dir\n";
    }

    system ("mkdir -p $template_dir");
    
    open (TP, ">${template_dir}/${node_file}");

    my $date=`date`;
    print TP "# Template generated at: $date";
    print TP "\n";

    print TP "type: txt\n";
    print TP "\n";

    print TP "help: Set $direction_term_hash{$direction} $table_help_hash{$table} ruleset name for interface\n";
    print TP "\n";

    print TP "allowed:\n";
    print TP "\tlocal -a params ;\n";
    print TP "\tparams=( /opt/vyatta/config/active/firewall/${table}/* )\n";
    print TP "\techo -n \${params[@]##*/}\n";
    print TP "\n";

    print TP "create:\n";
    print TP "\tifname=$if_name\n";
    print TP "\tsudo /opt/vyatta/sbin/vyatta-firewall.pl --update-interfaces \\\n";

    print TP "\t\tupdate \$ifname $direction \$VAR(@) $table\n";
    print TP "\n";
    print TP "update:\n";
    print TP "\tifname=$if_name\n";
    print TP "\tsudo /opt/vyatta/sbin/vyatta-firewall.pl --update-interfaces \\\n";
    print TP "\t\tupdate \$ifname $direction \$VAR(@) $table\n";
    print TP "\n";

    print TP "delete:\n";
    print TP "\tifname=$if_name\n";
    print TP "\tsudo /opt/vyatta/sbin/vyatta-firewall.pl --update-interfaces \\\n";
    print TP "\t\tdelete \$ifname $direction \$VAR(@) $table\n";
    
    close(TP);
}

my @ruleset_tables = ("name", "modify", "ipv6-name", "ipv6-modify");
my @ruleset_directions = ("in", "out", "local");

print "Generating interface templates...\n";

foreach my $if_tree (keys %interface_hash) {
    my $if_name = $interface_hash{$if_tree};

    if ($debug) {
	print "debug: if_tree=$if_tree if_name=$if_name \n";
    }

    gen_firewall_template($if_tree);
    for my $direction (@ruleset_directions) {
	gen_direction_template($if_tree, $direction);
	foreach my $table (@ruleset_tables) {
	    gen_template($if_tree, $direction, $table, $if_name);
	}
    }
}

print "Done.\n";

	

    
    
