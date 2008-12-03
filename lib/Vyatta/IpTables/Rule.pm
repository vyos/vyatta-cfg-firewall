package Vyatta::IpTables::Rule;

use Vyatta::Config;
require Vyatta::IpTables::AddressFilter;

my $src = new Vyatta::IpTables::AddressFilter;
my $dst = new Vyatta::IpTables::AddressFilter;

my %fields = (
  _name	       => undef,
  _rule_number => undef,
  _protocol    => undef,
  _state       => {
                    _established => undef,
                    _new         => undef,
                    _related     => undef,
                    _invalid     => undef,
                  },
  _action      => undef,
  _log         => undef,
  _icmp_code   => undef,
  _icmp_type   => undef,
  _mod_mark    => undef,
  _mod_dscp    => undef,
  _ipsec       => undef,
  _non_ipsec   => undef,
  _frag        => undef,
  _non_frag    => undef,
  _recent_time => undef,
  _recent_cnt  => undef,
  _p2p         => {
                    _all   => undef,
                    _apple => undef,
                    _bit   => undef,
                    _dc    => undef,
                    _edk   => undef,
                    _gnu   => undef,
                    _kazaa => undef,
                  },
);

my %dummy_rule = (
  _rule_number => 1025,
  _protocol    => "all",
  _state       => {
                    _established => undef,
                    _new         => undef,
                    _related     => undef,
                    _invalid     => undef,
                  },
  _action      => "DROP",
  _log         => undef,
  _icmp_code   => undef,
  _icmp_type   => undef,
  _mod_mark    => undef,
  _mod_dscp    => undef,
  _ipsec       => undef,
  _non_ipsec   => undef,
  _frag        => undef,
  _non_frag    => undef,
  _recent_time => undef,
  _recent_cnt  => undef,
  _p2p         => {
                    _all   => undef,
                    _apple => undef,
                    _bit   => undef,
                    _dc    => undef,
                    _edk   => undef,
                    _gnu   => undef,
                    _kazaa => undef,
                  },
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

sub setupDummy {
  my $self = shift;
  %{$self} = %dummy_rule;
  $src = new Vyatta::IpTables::AddressFilter;
  $dst = new Vyatta::IpTables::AddressFilter;
}

sub setup {
  my ( $self, $level ) = @_;
  my $config = new Vyatta::Config;

  $config->setLevel("$level");

  # for documentation sake.  nodes returns an array so must transform
  # and ".. .. .." means go up three levels in the current hierarchy
  $self->{_name}        = $config->returnParent(".. .. ..");
  $self->{_rule_number} = $config->returnParent("..");

  $self->{_protocol}  = $config->returnValue("protocol");
  $self->{_state}->{_established} = $config->returnValue("state established");
  $self->{_state}->{_new} = $config->returnValue("state new");
  $self->{_state}->{_related} = $config->returnValue("state related");
  $self->{_state}->{_invalid} = $config->returnValue("state invalid");
  $self->{_action}    = $config->returnValue("action");
  $self->{_log}       = $config->returnValue("log");
  $self->{_icmp_code} = $config->returnValue("icmp code");
  $self->{_icmp_type} = $config->returnValue("icmp type");
  $self->{_mod_mark} = $config->returnValue("modify mark");
  $self->{_mod_dscp} = $config->returnValue("modify dscp");
  $self->{_ipsec} = $config->exists("ipsec match-ipsec");
  $self->{_non_ipsec} = $config->exists("ipsec match-none");
  $self->{_frag} = $config->exists("fragment match-frag");
  $self->{_non_frag} = $config->exists("fragment match-non-frag");
  $self->{_recent_time} = $config->returnValue('recent time');
  $self->{_recent_cnt} = $config->returnValue('recent count');
  
  $self->{_p2p}->{_all} = $config->exists("p2p all");
  $self->{_p2p}->{_apple} = $config->exists("p2p applejuice");
  $self->{_p2p}->{_bit} = $config->exists("p2p bittorrent");
  $self->{_p2p}->{_dc} = $config->exists("p2p directconnect");
  $self->{_p2p}->{_edk} = $config->exists("p2p edonkey");
  $self->{_p2p}->{_gnu} = $config->exists("p2p gnutella");
  $self->{_p2p}->{_kazaa} = $config->exists("p2p kazaa");

  # TODO: need $config->exists("$level source") in Vyatta::Config.pm
  $src->setup("$level source");
  $dst->setup("$level destination");

  return 0;
}

sub setupOrig {
  my ( $self, $level ) = @_;
  my $config = new Vyatta::Config;

  $config->setLevel("$level");

  # for documentation sake.  nodes returns an array so must transform
  # and ".. .. .." means go up three levels in the current hierarchy
  $self->{_name}        = $config->returnParent(".. .. ..");
  $self->{_rule_number} = $config->returnParent("..");

  $self->{_protocol}  = $config->returnOrigValue("protocol");
  $self->{_state}->{_established}
    = $config->returnOrigValue("state established");
  $self->{_state}->{_new} = $config->returnOrigValue("state new");
  $self->{_state}->{_related} = $config->returnOrigValue("state related");
  $self->{_state}->{_invalid} = $config->returnOrigValue("state invalid");
  $self->{_action}    = $config->returnOrigValue("action");
  $self->{_log}       = $config->returnOrigValue("log");
  $self->{_icmp_code} = $config->returnOrigValue("icmp code");
  $self->{_icmp_type} = $config->returnOrigValue("icmp type");
  $self->{_mod_mark} = $config->returnOrigValue("modify mark");
  $self->{_mod_dscp} = $config->returnOrigValue("modify dscp");
  $self->{_ipsec} = $config->existsOrig("ipsec match-ipsec");
  $self->{_non_ipsec} = $config->existsOrig("ipsec match-none");
  $self->{_frag} = $config->existsOrig("fragment match-frag");
  $self->{_non_frag} = $config->existsOrig("fragment match-non-frag");
  $self->{_recent_time} = $config->returnOrigValue('recent time');
  $self->{_recent_cnt} = $config->returnOrigValue('recent count');

  $self->{_p2p}->{_all} = $config->existsOrig("p2p all");
  $self->{_p2p}->{_apple} = $config->existsOrig("p2p applejuice");
  $self->{_p2p}->{_bit} = $config->existsOrig("p2p bittorrent");
  $self->{_p2p}->{_dc} = $config->existsOrig("p2p directconnect");
  $self->{_p2p}->{_edk} = $config->existsOrig("p2p edonkey");
  $self->{_p2p}->{_gnu} = $config->existsOrig("p2p gnutella");
  $self->{_p2p}->{_kazaa} = $config->existsOrig("p2p kazaa");

  # TODO: need $config->exists("$level source") in Vyatta::Config.pm
  $src->setupOrig("$level source");
  $dst->setupOrig("$level destination");

  return 0;
}

sub print {
  my ( $self ) = @_;

  print "name: $self->{_name}\n"	   if defined $self->{_name};
  print "rulenum: $self->{_rule_number}\n" if defined $self->{_rule_number};
  print "protocol: $self->{_protocol}\n"   if defined $self->{_protocol};
  print "state: $self->{_state}\n"         if defined $self->{_state};
  print "action: $self->{_action}\n"       if defined $self->{_action};
  print "log: $self->{_log}\n"             if defined $self->{_log};
  print "icmp code: $self->{_icmp_code}\n" if defined $self->{_icmp_code};
  print "icmp type: $self->{_icmp_type}\n" if defined $self->{_icmp_type};
  print "mod mark: $self->{_mod_mark}\n"   if defined $self->{_mod_mark};
  print "mod dscp: $self->{_mod_dscp}\n"   if defined $self->{_mod_dscp};

  $src->print();
  $dst->print();

}

sub is_stateful {
  my $self = shift;
  my @states = qw(established new related invalid);
  foreach (@states) {
    if (defined($self->{_state}->{"_$_"})
        && $self->{_state}->{"_$_"} eq "enable") {
      return 1;
    }
  }
  return 0;
}

sub get_state_str {
  my $self = shift;
  my @states = qw(established new related invalid);
  my @add_states = ();
  foreach (@states) {
    if (defined($self->{_state}->{"_$_"})
        && $self->{_state}->{"_$_"} eq "enable") {
      push @add_states, $_;
    }
  }
  if ($#add_states >= 0) {
    my $str = join ',', @add_states;
    return $str;
  } else {
    return "";
  }
}

sub get_num_ipt_rules {
  my $self = shift;
  my $ipt_rules = 1;
  if (("$self->{_log}" eq "enable") && (("$self->{_action}" eq "drop")
                                        || ("$self->{_action}" eq "accept")
                                        || ("$self->{_action}" eq "reject")
                                        || ("$self->{_action}" eq "modify"))) {
    $ipt_rules += 1;
  }
  if (defined($self->{_recent_time}) || defined($self->{_recent_cnt})) {
    $ipt_rules += 1;
  }
  return $ipt_rules;
}

sub rule {
  my ( $self ) = @_;
  my $rule = undef;
  my $srcrule = $dstrule = undef;
  my $err_str = undef;

  # set the protocol
  if (defined($self->{_protocol})) {
    my $str = $self->{_protocol};
    $str =~ s/^\!(.*)$/! $1/;
    $rule .= "--protocol $str ";
  }

  # set the session state if protocol tcp
  my $state_str = uc (get_state_str($self));
  if ($state_str ne "") {
    $rule .= "-m state --state $state_str ";
  }

  # set the icmp code and type if applicable
  if (($self->{_protocol} eq "icmp") || ($self->{_protocol} eq "1")) {
    if (defined $self->{_icmp_type}) {
      $rule .= "--icmp-type $self->{_icmp_type}";
      if (defined $self->{_icmp_code}) {
        $rule .= "/$self->{_icmp_code}";
      }
      $rule .= " ";
    } elsif (defined $self->{_icmp_code}) {
      return ("ICMP code can only be defined if ICMP type is defined", );
              
    }
  } elsif (defined($self->{_icmp_type}) || defined($self->{_icmp_code})) {
    return ("ICMP type/code can only be defined if protocol is ICMP", );
  }

  # add the source and destination rules
  ($srcrule, $err_str) = $src->rule();
  return ($err_str, ) if (!defined($srcrule));
  ($dstrule, $err_str) = $dst->rule();
  return ($err_str, ) if (!defined($dstrule));
  if ((grep /multiport/, $srcrule) || (grep /multiport/, $dstrule)) {
    if ((grep /sport/, $srcrule) && (grep /dport/, $dstrule)) {
      return ('Cannot specify multiple ports when both '
              . 'source and destination ports are specified', );
    }
  }
  $rule .= " $srcrule $dstrule ";

  return ('Cannot specify both "match-frag" and "match-non-frag"', )
    if (defined($self->{_frag}) && defined($self->{_non_frag}));
  if (defined($self->{_frag})) {
    $rule .= ' -f ';
  } elsif (defined($self->{_non_frag})) {
    $rule .= ' ! -f ';
  }

  # note: "out" is not valid in the INPUT chain.
  return ('Cannot specify both "match-ipsec" and "match-none"', )
    if (defined($self->{_ipsec}) && defined($self->{_non_ipsec}));
  if (defined($self->{_ipsec})) {
    $rule .= ' -m policy --pol ipsec --dir in ';
  } elsif (defined($self->{_non_ipsec})) {
    $rule .= ' -m policy --pol none --dir in ';
  }

  my $recent_rule = undef;
  if (defined($self->{_recent_time}) || defined($self->{_recent_cnt})) {
    $recent_rule = $rule;
    $rule .= ' -m recent --update ';
    $recent_rule .= ' -m recent --set ';
    if (defined($self->{_recent_time})) {
      $rule .= " --seconds $self->{_recent_time} ";
    }
    if (defined($self->{_recent_cnt})) {
      $rule .= " --hitcount $self->{_recent_cnt} ";
    }
  }

  my $p2p = undef;
  if (defined($self->{_p2p}->{_all})) {
    $p2p = '--apple --bit --dc --edk --gnu --kazaa ';
  } else {
    my @apps = qw(apple bit dc edk gnu kazaa);
    foreach (@apps) {
      if (defined($self->{_p2p}->{"_$_"})) {
        $p2p .= "--$_ ";
      }
    }
  }
  if (defined($p2p)) {
    $rule .= " -m ipp2p $p2p ";
  }

  my $chain = $self->{_name};
  my $rule_num = $self->{_rule_number};
  my $rule2 = undef;
  # set the jump target.  Depends on action and log
  if ("$self->{_log}" eq "enable") {
    $rule2 = $rule;
    $rule2 .= "-j LOG --log-prefix '[$chain $rule_num $self->{_action}] ' ";
  }
  if ("$self->{_action}" eq "drop") {
    $rule .= "-j DROP ";
  } elsif ("$self->{_action}" eq "accept") {
    $rule .= "-j RETURN ";
  } elsif ("$self->{_action}" eq "reject") {
    $rule .= "-j REJECT ";
  } elsif ("$self->{_action}" eq 'inspect') {
    $rule .= "-j QUEUE ";
  } elsif ("$self->{_action}" eq 'modify') {
    # mangle actions
    my $count = 0;
    if (defined($self->{_mod_mark})) {
      # MARK
      $rule .= "-j MARK --set-mark $self->{_mod_mark} ";
      $count++;
    }
    if (defined($self->{_mod_dscp})) {
      # DSCP
      $rule .= "-j DSCP --set-dscp $self->{_mod_dscp} ";
      $count++;
    }
    
    # others

    if ($count == 0) {
      return ('Action "modify" requires more specific configuration under '
              . 'the "modify" node', );
    } elsif ($count > 1) {
      return ('Cannot define more than one modification under '
              . 'the "modify" node', );
    }
  } else {
    return ("\"action\" must be defined", );
  }
  if (defined($rule2)) {
    my $tmp = $rule2;
    $rule2 = $rule;
    $rule = $tmp;
  } elsif (defined($recent_rule)) {
    $rule2 = $recent_rule;
    $recent_rule = undef;
  }
  return (undef, $rule, $rule2, $recent_rule, );
}

sub outputXmlElem {
  my ($name, $value, $fh) = @_;
  print $fh "    <$name>$value</$name>\n";
}

sub outputXml {
  my ($self, $fh) = @_;
  outputXmlElem("protocol", $self->{_protocol}, $fh);
  my $state_str = get_state_str($self);
  if ($state_str ne "") {
    $state_str =~ s/,/%2C/g;
    $state_str .= "+";
  }
  outputXmlElem("state", $state_str, $fh);
  outputXmlElem("action", uc($self->{_action}), $fh);
  outputXmlElem("log", $self->{_log}, $fh);
  outputXmlElem("icmp_type", $self->{_icmp_type}, $fh);
  outputXmlElem("icmp_code", $self->{_icmp_code}, $fh);
  
  $src->outputXml("src", $fh);  
  $dst->outputXml("dst", $fh);  
}

1;
