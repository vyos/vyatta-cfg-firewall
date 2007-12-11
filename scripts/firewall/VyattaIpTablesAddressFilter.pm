package VyattaIpTablesAddressFilter;

use VyattaConfig;

my %_protocolswithports = (
  tcp => 1,
  udp => 1,
  6   => 1,
  17  => 1,
);

my %fields = (
  _srcdst	   => undef,
  _range_start     => undef,
  _range_stop      => undef,
  _network         => undef,
  _address         => undef,
  _portname        => undef,
  _portrange_start => undef,
  _portrange_stop  => undef,
  _portnumber      => undef,
  _protocol        => undef,
  _src_mac         => undef,
);

sub new {
  my $that = shift;
  my $class = ref ($that) || $that;
  my $self = {
    %fields,
  };

  bless $self, $class;
  return $self;
}

sub setup {
  my ($self, $level) = @_;
  my $config = new VyattaConfig;

  $config->setLevel("$level");

  # setup needed parent nodes
  $self->{_srcdst}          = $config->returnParent("..");
  $self->{_protocol}        = $config->returnValue(".. protocol");

  # setup address filter nodes
  $self->{_range_start}     = $config->returnValue("range start");
  $self->{_range_stop}      = $config->returnValue("range stop");
  $self->{_network}         = $config->returnValue("network");
  $self->{_address}         = $config->returnValue("address");
  my @tmp                   = $config->returnValues("port-number");
  $self->{_portnumber}      = [ @tmp ]; 
  @tmp                      = $config->returnValues("port-name");
  $self->{_portname}        = [ @tmp ];
  $self->{_portrange_start} = $config->returnValue("port-range start");
  $self->{_portrange_stop}  = $config->returnValue("port-range stop");
  
  $self->{_src_mac}  = $config->returnValue("mac-address");

  return 0;
}

sub setupOrig {
  my ($self, $level) = @_;
  my $config = new VyattaConfig;

  $config->setLevel("$level");

  # setup needed parent nodes
  $self->{_srcdst}          = $config->returnParent("..");
  $self->{_protocol}        = $config->returnOrigValue(".. protocol");

  # setup address filter nodes
  $self->{_range_start}     = $config->returnOrigValue("range start");
  $self->{_range_stop}      = $config->returnOrigValue("range stop");
  $self->{_network}         = $config->returnOrigValue("network");
  $self->{_address}         = $config->returnOrigValue("address");
  my @tmp                   = $config->returnOrigValues("port-number");
  $self->{_portnumber}      = [ @tmp ]; 
  @tmp                      = $config->returnOrigValues("port-name");
  $self->{_portname}        = [ @tmp ]; 
  $self->{_portrange_start} = $config->returnOrigValue("port-range start");
  $self->{_portrange_stop}  = $config->returnOrigValue("port-range stop");

  $self->{_src_mac}  = $config->returnValue("mac-address");

  return 0;
}

sub print {
  my ($self) = @_;

  print "srcdst: $self->{_srcdst}\n"           	 	if defined $self->{_srcdst};
  print "range start: $self->{_range_start}\n"          if defined $self->{_range_start};
  print "range stop: $self->{_range_stop}\n"            if defined $self->{_range_stop};
  print "network: $self->{_network}\n"                  if defined $self->{_network};
  print "address: $self->{_address}\n"                  if defined $self->{_address};
  print "port-name: " . (join ',', $self->{_portname}) . "\n"
    if defined $self->{_portname};
  print "port-range start: $self->{_portrange_start}\n" if defined $self->{_portrange_start};
  print "port-range stop: $self->{_portrange_stop}\n"   if defined $self->{_portrange_stop};
  print "port-number: " . (join ',', $self->{_portnumber}) . "\n"
    if defined $self->{_portnumber};
  print "protocol: $self->{_protocol}\n"		if defined $self->{_protocol};
  print "src-mac: $self->{_src_mac}\n"		if defined $self->{_src_mac};

  return 0;
}

sub handle_ports {
  my $num_ref = shift;
  my $name_ref = shift;
  my $pstart = shift;
  my $pstop = shift;
  my $can_use_port = shift;
  my $prefix = shift;
  my $proto = shift;

  my $rule_str = "";
  my ($ports, $prange) = (0, 0);
  my @pnums = @{$num_ref};
  my @pnames = @{$name_ref};
  $ports = ($#pnums + 1) + ($#pnames + 1);

  if (defined($pstart) && defined($pstop)) {
    if ($pstop < $pstart) {
      return (undef, "invalid port range $pstart-$pstop");
    }
    $ports += ($pstop - $pstart + 1);
    $prange = ($pstop - $pstart - 1);
  }
  if (($ports > 0) && (!$can_use_port)) {
    return (undef, "ports can only be specified when protocol is \"tcp\" "
                   . "or \"udp\" (currently \"$proto\")");
  }
  if (($ports - $prange) > 15) {
    return (undef, "source/destination port specification only supports "
                   . "up to 15 ports (port range counts as 2)");
  }
  if ($ports > 1) {
    $rule_str .= " -m multiport --${prefix}ports ";
    my $first = 1; 
    if ($#pnums >= 0) {
      my $pstr = join(',', @pnums);
      $rule_str .= "$pstr";
      $first = 0;
    }
    if ($#pnames >= 0) {
      if ($first == 0) {
        $rule_str .= ",";
      }
      my $pstr = join(',', @pnames);
      $rule_str .= "$pstr";
      $first = 0;
    }
    if (defined($pstart) && defined($pstop)) {
      if ($first == 0) {
        $rule_str .= ",";
      }
      if ($pstart == $pstop) {
        $rule_str .= "$pstart";
      } else {
        $rule_str .= "$pstart:$pstop";
      }
      $first = 0;
    }
  } elsif ($ports > 0) {
    $rule_str .= " --${prefix}port ";
    if ($#pnums >= 0) {
      $rule_str .= "$pnums[0]";
    } elsif ($#pnames >= 0) {
      $rule_str .= "$pnames[0]";
    } else {
      # no number, no name, range of 1
      $rule_str .= "$pstart";
    }
  }
  return ($rule_str, undef);
}

sub rule {
  my ($self) = @_;
  my $rule = "";
  my $can_use_port = 1;
  
  if (!defined($self->{_protocol})
      || !defined($_protocolswithports{$self->{_protocol}})) {
    $can_use_port = 0;
  }

  if (($self->{_srcdst} eq "source") && (defined($self->{_src_mac}))) {
    # handle src mac
    my $str = $self->{_src_mac};
    $str =~ s/^\!(.*)$/! $1/;
    $rule .= "-m mac --mac-source $str ";
  }

  # set the address filter parameters
  if (defined($self->{_network})) {
    my $str = $self->{_network};
    $str =~ s/^\!(.*)$/! $1/;
    $rule .= "--$self->{_srcdst} $str ";
  } elsif (defined($self->{_address})) {
    my $str = $self->{_address};
    $str =~ s/^\!(.*)$/! $1/;
    $rule .= "--$self->{_srcdst} $str ";
  } elsif ((defined $self->{_range_start}) && (defined $self->{_range_stop})) {
    if ("$self->{_srcdst}" eq "source") { 
      $rule .= ("-m iprange " 
                . "--src-range $self->{_range_start}-$self->{_range_stop} ");
    }
    elsif ("$self->{_srcdst}" eq "destination") { 
      $rule .= ("-m iprange "
                . "--dst-range $self->{_range_start}-$self->{_range_stop} ");
    }
  }

  my ($port_str, $port_err)
    = handle_ports($self->{_portnumber},
                   $self->{_portname},
                   $self->{_portrange_start},
                   $self->{_portrange_stop},
                   $can_use_port,
                   ($self->{_srcdst} eq "source") ? "s" : "d",
                   $self->{_protocol});
  return (undef, $port_err) if (!defined($port_str));
  $rule .= $port_str;
  return ($rule, undef);
}

sub outputXmlElem {
  my ($name, $value, $fh) = @_;
  print $fh "    <$name>$value</$name>\n";
}

sub outputXml {
  my ($self, $prefix, $fh) = @_;
  outputXmlElem("${prefix}_addr", $self->{_address}, $fh);
  outputXmlElem("${prefix}_net", $self->{_network}, $fh);
  outputXmlElem("${prefix}_addr_start", $self->{_range_start}, $fh);
  outputXmlElem("${prefix}_addr_stop", $self->{_range_stop}, $fh);
  outputXmlElem("${prefix}_port_num",
                (join ',', @{$self->{_portnumber}}), $fh);
  outputXmlElem("${prefix}_port_name",
                (join ',', @{$self->{_portname}}), $fh);
  outputXmlElem("${prefix}_port_start", $self->{_portrange_start}, $fh);
  outputXmlElem("${prefix}_port_stop", $self->{_portrange_stop}, $fh);
}

