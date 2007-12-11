package VyattaIpTablesRule;

use VyattaConfig;
use VyattaIpTablesAddressFilter;

my $src = new VyattaIpTablesAddressFilter;
my $dst = new VyattaIpTablesAddressFilter;

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
  $src = new VyattaIpTablesAddressFilter;
  $dst = new VyattaIpTablesAddressFilter;
}

sub setup {
  my ( $self, $level ) = @_;
  my $config = new VyattaConfig;

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

  # TODO: need $config->exists("$level source") in VyattaConfig.pm
  $src->setup("$level source");
  $dst->setup("$level destination");

  return 0;
}

sub setupOrig {
  my ( $self, $level ) = @_;
  my $config = new VyattaConfig;

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

  # TODO: need $config->exists("$level source") in VyattaConfig.pm
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
                                        || ("$self->{_action}" eq "reject"))) {
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
  $rule .= " $srcrule $dstrule ";

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
  } else {
    return ("\"action\" must be defined", );
  }
  if (defined($rule2)) {
    my $tmp = $rule2;
    $rule2 = $rule;
    $rule = $tmp;
  }
  return (undef, $rule, $rule2, );
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

