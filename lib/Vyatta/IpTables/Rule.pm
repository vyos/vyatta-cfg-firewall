package Vyatta::IpTables::Rule;

use strict;
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
  _tcp_flags   => undef,
  _icmp_code   => undef,
  _icmp_type   => undef,
  _icmp_name   => undef,
  _icmpv6_type => undef,
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
  _time        => {
                   _startdate => undef,
                   _stopdate  => undef,
                   _starttime => undef,
                   _stoptime  => undef,
                   _monthdays => undef,
                   _weekdays  => undef,
                   _utc       => undef,
                  },
  _limit       => {
                    _rate     => undef,
                    _burst    => undef,
                  },
  _disable     => undef,
  _ip_version  => undef,
  _comment     => undef
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
  _tcp_flags   => undef,
  _icmp_code   => undef,
  _icmp_type   => undef,
  _icmp_name   => undef,
  _icmpv6_type => undef,
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
  _time        => {
                   _startdate => undef,
                   _stopdate  => undef,
                   _starttime => undef,
                   _stoptime  => undef,
                   _monthdays => undef,
                   _weekdays  => undef,
                   _utc       => undef,
                  },
  _limit       => {
                    _rate     => undef,
                    _burst    => undef,
                  },
  _disable     => undef,
  _ip_version  => undef,
  _comment     => undef
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

sub setup_base {
  my ($self, $level, $val_func, $exists_func, $addr_setup) = @_;
  my $config = new Vyatta::Config;

  $self->{_comment} = $level;
  $config->setLevel("$level");

  # for documentation sake.  nodes returns an array so must transform
  # and ".. .. .." means go up three levels in the current hierarchy
  $self->{_name}        = $config->returnParent(".. .. ..");
  $self->{_rule_number} = $config->returnParent("..");

  $self->{_protocol}    = $config->$val_func("protocol");

  $self->{_state}->{_established} = $config->$val_func("state established");
  $self->{_state}->{_new}         = $config->$val_func("state new");
  $self->{_state}->{_related}     = $config->$val_func("state related");
  $self->{_state}->{_invalid}     = $config->$val_func("state invalid");

  $self->{_action}      = $config->$val_func("action");
  $self->{_log}         = $config->$val_func("log");
  $self->{_tcp_flags}   = $config->$val_func("tcp flags");
  $self->{_icmp_code}   = $config->$val_func("icmp code");
  $self->{_icmp_type}   = $config->$val_func("icmp type");
  $self->{_icmp_name}   = $config->$val_func("icmp type-name");
  $self->{_icmpv6_type} = $config->$val_func("icmpv6 type");
  $self->{_mod_mark}    = $config->$val_func("modify mark");
  $self->{_mod_dscp}    = $config->$val_func("modify dscp");
  $self->{_ipsec}       = $config->$exists_func("ipsec match-ipsec");
  $self->{_non_ipsec}   = $config->$exists_func("ipsec match-none");
  $self->{_frag}        = $config->$exists_func("fragment match-frag");
  $self->{_non_frag}    = $config->$exists_func("fragment match-non-frag");
  $self->{_recent_time} = $config->$val_func('recent time');
  $self->{_recent_cnt}  = $config->$val_func('recent count');
  
  $self->{_p2p}->{_all}   = $config->$exists_func("p2p all");
  $self->{_p2p}->{_apple} = $config->$exists_func("p2p applejuice");
  $self->{_p2p}->{_bit}   = $config->$exists_func("p2p bittorrent");
  $self->{_p2p}->{_dc}    = $config->$exists_func("p2p directconnect");
  $self->{_p2p}->{_edk}   = $config->$exists_func("p2p edonkey");
  $self->{_p2p}->{_gnu}   = $config->$exists_func("p2p gnutella");
  $self->{_p2p}->{_kazaa} = $config->$exists_func("p2p kazaa");

  $self->{_time}->{_startdate} = $config->$val_func("time startdate");
  $self->{_time}->{_stopdate}  = $config->$val_func("time stopdate");
  $self->{_time}->{_starttime} = $config->$val_func("time starttime");
  $self->{_time}->{_stoptime}  = $config->$val_func("time stoptime");
  $self->{_time}->{_monthdays} = $config->$val_func("time monthdays");
  $self->{_time}->{_weekdays}  = $config->$val_func("time weekdays");
  $self->{_time}->{_utc}       = $config->$exists_func("time utc");

  $self->{_limit}->{_rate}  = $config->$val_func("limit rate");
  $self->{_limit}->{_burst} = $config->$val_func("limit burst");

  $self->{_disable} = $config->$exists_func("disable");

  # TODO: need $config->exists("$level source") in Vyatta::Config.pm
  $src->$addr_setup("$level source");
  $dst->$addr_setup("$level destination");

  # Default to IPv4
  $self->{_ip_version} = "ipv4";
  return 0;
}

sub setup {
  my ($self, $level) = @_;
  
  $self->setup_base($level, 'returnValue', 'exists', 'setup');
  return 0;
}

sub setupOrig {
  my ($self, $level) = @_;
  
  $self->setup_base($level, 'returnOrigValue', 'existsOrig', 'setupOrig');

  $self->{_ip_version} = "ipv4";
  return 0;
}

sub set_ip_version {
  my ($self, $ip_version) = @_;

  $self->{_ip_version} = $ip_version;
  $src->set_ip_version($ip_version);
  $dst->set_ip_version($ip_version);
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
  print "icmpv6 type: $self->{_icmpv6_type}\n"
                                           if defined $self->{_icmpv6_type};
  print "mod mark: $self->{_mod_mark}\n"   if defined $self->{_mod_mark};
  print "mod dscp: $self->{_mod_dscp}\n"   if defined $self->{_mod_dscp};

  $src->print();
  $dst->print();

}

sub is_stateful {
  my $self = shift;
  return 0 if defined $self->{_disable};
  my @states = qw(established new related invalid);
  foreach (@states) {
    if (defined($self->{_state}->{"_$_"})
        && $self->{_state}->{"_$_"} eq "enable") {
      return 1;
    }
  }
  return 0;
}

sub is_disabled {
  my $self = shift;
  return 1 if defined $self->{_disable};
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
  return 0 if defined $self->{_disable};
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
  my ($rule, $srcrule, $dstrule, $err_str);

  # set CLI rule num as comment
  my @level_nodes = split (' ', $self->{_comment});
  $rule .= "-m comment --comment \"$level_nodes[2]-$level_nodes[4]\" ";

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

  # set tcp flags if applicable
  my $tcp_flags = undef;
  if (defined $self->{_tcp_flags}) {
   if (($self->{_protocol} eq "tcp") || ($self->{_protocol} eq "6")) {
      $tcp_flags = get_tcp_flags_string($self->{_tcp_flags});
    } else {
      return ("TCP flags can only be set if protocol is set to TCP", );
    }
  }
  if (defined($tcp_flags)) {
    $rule .= " -m tcp --tcp-flags $tcp_flags ";
  }

  # set the icmp code and type if applicable
  if (($self->{_protocol} eq "icmp") || ($self->{_protocol} eq "1")) {
   if (defined $self->{_icmp_name}) {
     if (defined($self->{_icmp_type}) || defined($self->{_icmp_code})){
      return ("Cannot use ICMP type/code with ICMP type-name", );
     }
     $rule .= "--icmp-type $self->{_icmp_name} ";
   } elsif (defined $self->{_icmp_type}) {
      $rule .= "--icmp-type $self->{_icmp_type}";
      if (defined $self->{_icmp_code}) {
        $rule .= "/$self->{_icmp_code}";
      }
      $rule .= " ";
   } elsif (defined $self->{_icmp_code}) {
      return ("ICMP code can only be defined if ICMP type is defined", );
   }
  } elsif (defined($self->{_icmp_type}) || defined($self->{_icmp_code}) 
           || defined($self->{_icmp_name})) {
     return ("ICMP type/code or type-name can only be defined if protocol is ICMP", );
  }

  # Setup ICMPv6 rule if configured
  # ICMPv6 parameters are only valid if the rule is matching on the 
  # ICMPv6 protocol ID.
  # 
  if (($self->{_protocol} eq "icmpv6") || 
      ($self->{_protocol} eq "ipv6-icmp") || 
      ($self->{_protocol} eq "58")) {
    if (defined($self->{_icmpv6_type})) {
      $rule .= "-m icmpv6 --icmpv6-type $self->{_icmpv6_type}";
    }
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

  my $time = undef;
  if (defined($self->{_time}->{_utc})) {
      $time .= " --utc ";
  }
  if (defined($self->{_time}->{_startdate})) {
   my $check_date = validate_date($self->{_time}->{_startdate}, "startdate");
   if (!($check_date eq "")) {
     return ($check_date, );
   }
   $time .= " --datestart $self->{_time}->{_startdate} ";
  }
  if (defined($self->{_time}->{_stopdate})) {
   my $check_date = validate_date($self->{_time}->{_stopdate}, "stopdate");
   if (!($check_date eq "")) {
     return ($check_date, );
   }
   $time .= " --datestop $self->{_time}->{_stopdate} ";
  }
  if (defined($self->{_time}->{_starttime})) {
  return ("Invalid starttime $self->{_time}->{_starttime}.
Time should use 24 hour notation hh:mm:ss and lie in between 00:00:00 and 23:59:59", )
    if (!validate_timevalues($self->{_time}->{_starttime}, "time"));
      $time .= " --timestart $self->{_time}->{_starttime} ";
  }
  if (defined($self->{_time}->{_stoptime})) {
  return ("Invalid stoptime $self->{_time}->{_stoptime}.
Time should use 24 hour notation hh:mm:ss and lie in between 00:00:00 and 23:59:59", )
    if (!validate_timevalues($self->{_time}->{_stoptime}, "time"));
      $time .= " --timestop $self->{_time}->{_stoptime} ";
  }
  if (defined($self->{_time}->{_monthdays})) {
      my $negate = " ";
      if ($self->{_time}->{_monthdays} =~ m/^!/) {
          $negate = "! ";
          $self->{_time}->{_monthdays} = substr $self->{_time}->{_monthdays}, 1;
      }
  return ("Invalid monthdays value $self->{_time}->{_monthdays}.
Monthdays should have values between 1 and 31 with multiple days separated by commas
eg. 2,12,21 For negation, add ! in front eg. !2,12,21", )
    if (!validate_timevalues($self->{_time}->{_monthdays}, "monthdays"));
      $time .= " $negate --monthdays $self->{_time}->{_monthdays} ";
  }
  if (defined($self->{_time}->{_weekdays})) {
      my $negate = " ";
      if ($self->{_time}->{_weekdays} =~ m/^!/) {
          $negate = "! ";
          $self->{_time}->{_weekdays} = substr $self->{_time}->{_weekdays}, 1;
      }
  return ("Invalid weekdays value $self->{_time}->{_weekdays}.
Weekdays should be specified using the first three characters of the day with the
first character capitalized eg. Mon,Thu,Sat For negation, add ! in front eg. !Mon,Thu,Sat", )
    if (!validate_timevalues($self->{_time}->{_weekdays}, "weekdays"));
      $time .= " $negate --weekdays $self->{_time}->{_weekdays} ";
  }
  if (defined($time)) {
    $rule .= " -m time $time ";
  }

  my $limit = undef;
  if (defined($self->{_limit}->{_burst})) {
    return ("Limit rate not defined", ) if (!defined($self->{_limit}->{_rate}));
    $limit = "--limit $self->{_limit}->{_rate} --limit-burst $self->{_limit}->{_burst}";
  } elsif (defined($self->{_limit}->{_rate})) {
     $limit = "--limit $self->{_limit}->{_rate} --limit-burst 1";
  }
  if (defined($limit)) {
    $rule .= " -m limit $limit ";
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
  return (undef, undef) if defined $self->{_disable};
  return (undef, $rule, $rule2, $recent_rule, );
}

sub outputXmlElem {
  my ($name, $value, $fh) = @_;
  print $fh "    <$name>$value</$name>\n";
}

sub outputXml {
  my ($self, $fh) = @_;
  if (!defined($self->{_protocol})) {
   $self->{_protocol} = "all";
  }
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

sub validate_timevalues {
 my ($string, $type) = @_;
 use Switch;
 use Time::Local;
 switch ($type) {
  case "date"      { $string =~ s/-//g;
                     my ($year, $month, $day) = unpack "A4 A2 A2", $string;
                     eval { timelocal(0,0,0,$day, $month-1, $year);
                            1;
                          } or return 0;
                   }

  case "time"      { $string =~ s/://g;
                     my ($hour, $min, $sec) = unpack "A2 A2 A2", $string;
                     eval { timelocal($sec,$min,$hour, 1, 0, 1970);
                            1;
                          } or return 0;
                   }

  case "monthdays" { while($string =~ m/(\d+)/g) {
                        if ($1 < 1 || $1 > 31) {
                           return 0;
                        }
                     }
                   }

  case "weekdays"  { my @weekdays = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun");
                     while($string =~ m/(\w+)/g) {
                        if (!grep(/$1/,@weekdays)) {
                           return 0;
                        }
                     }
                   }

  else             { print
                     "Invalid type '$type' passed to sub validate_timevalues()\n";
		     return 0;
                   }
 }
  return 1;
}

sub validate_date {

 my ($date, $string) = @_;
 if ($date =~ m/T/) {
     my $actualdate = substr $date, 0 , 10;
     my $datetime = substr $date, 11;
     return ("Invalid  $string $actualdate.
Date should use yyyy-mm-dd format and lie in between 1970-01-01 and 2038-01-19")
     if (!validate_timevalues($actualdate, "date"));
     return ("Invalid time $datetime for $string $actualdate.
Time should use 24 hour notation hh:mm:ss and lie in between 00:00:00 and 23:59:59")
     if (!validate_timevalues($datetime, "time"));
   } else {
      return ("Invalid $string $date.
Date should use yyyy-mm-dd format and lie in between 1970-01-01 and 2038-01-19")
      if (!validate_timevalues($date, "date"));
   }
 return ("");
}

sub get_tcp_flags_string {

 my $string = shift;
 my @list_of_flags = (); # list of tcp flags to be examined
 my @list_of_set_flags = (); # list of flags which must be set

 my @string_list = split(/,/, $string);
 while(@string_list) {
  if (!grep(/!/,$string_list[0])) {
   push @list_of_flags, $string_list[0];
   push @list_of_set_flags, $string_list[0];
  } else {
    $string_list[0] =~ s/!//g;
    push @list_of_flags, $string_list[0];
  }
  shift(@string_list);
 }

 push @list_of_set_flags, 'NONE' if @list_of_set_flags == ();
 return join(",",@list_of_flags) . " " . join(",",@list_of_set_flags);
}

1;

# Local Variables:
# mode: perl
# indent-tabs-mode: nil
# perl-indent-level: 2
# End:
