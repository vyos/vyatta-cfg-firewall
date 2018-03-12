# Author: Vyatta <eng@vyatta.com>
# Date: 2007
# Description: IP tables address filter

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
# Portions created by Vyatta are Copyright (C) 2006-2009 Vyatta, Inc.
# All Rights Reserved.
# **** End License ****

package Vyatta::IpTables::AddressFilter;

require Vyatta::Config;
require Vyatta::IpTables::IpSet;
use Vyatta::Misc qw(getPortRuleString);
use Vyatta::TypeChecker;

use strict;
use warnings;

my %_protocolswithports = (
    tcp_udp => 1,

    # 'tcp_udp' is to be allowed for nat and firewall rules only.
    # features should have syntax checks for allowing or forbiding
    # the use of 'tcp_udp' as protocol. to allow tcp_udp see syntax check
    # in protocol/node.def for NAT rules and to forbid tcp_udp see syntax
    # check in protocol/node.def for load-balancing rules
    # when allowed : tcp_udp creates 2 iptable rules - one for tcp, other for udp
    tcp => 1,
    udp => 1,
    6   => 1,
    17  => 1,
);

my %fields = (
    _srcdst        => undef,
    _range_start   => undef,
    _range_stop    => undef,
    _network       => undef,
    _address       => undef,
    _port          => undef,
    _protocol      => undef,
    _src_mac       => undef,
    _ip_version    => undef,
    _address_group => undef,
    _network_group => undef,
    _port_group    => undef,
);

sub new {
    my $that = shift;
    my $class = ref($that) || $that;
    my $self = {%fields,};

    bless $self, $class;
    return $self;
}

sub set_ip_version {
    my ($self, $ip_version) = @_;

    $self->{_ip_version} = $ip_version;
}

sub setup_base {
    my ($self, $level, $func) = @_;
    my $config = new Vyatta::Config;

    $config->setLevel("$level");

    # Default to IPv4.
    $self->{_ip_version} = "ipv4";

    # setup needed parent nodes
    $self->{_srcdst} = $config->returnParent("..");
    $self->{_protocol} = $config->$func(".. protocol");

    # setup address filter nodes
    $self->{_address} = $config->$func("address");
    $self->{_network} = undef;
    $self->{_range_start} = undef;
    $self->{_range_stop} = undef;
    if (defined($self->{_address})) {
        if ($self->{_address} =~ /\//) {
            $self->{_network} = $self->{_address};
            $self->{_address} = undef;
        } elsif ($self->{_address} =~ /^([^-]+)-([^-]+)$/) {
            $self->{_range_start} = $1;
            $self->{_range_stop} = $2;
            $self->{_address} = undef;
        }
    }

    $self->{_port} = $config->$func("port");
    $self->{_src_mac} = $config->$func("mac-address");
    $self->{_address_group} = $config->$func("group address-group");
    $self->{_network_group} = $config->$func("group network-group");
    $self->{_port_group} = $config->$func("group port-group");

    return 0;
}

sub setup {
    my ($self, $level) = @_;

    $self->setup_base($level, 'returnValue');
    return 0;
}

sub setupOrig {
    my ($self, $level) = @_;

    $self->setup_base($level, 'returnOrigValue');
    return 0;
}

sub print {
    my ($self) = @_;

    print "srcdst: $self->{_srcdst}\n"            if defined $self->{_srcdst};
    print "range start: $self->{_range_start}\n"  if defined $self->{_range_start};
    print "range stop: $self->{_range_stop}\n"    if defined $self->{_range_stop};
    print "network: $self->{_network}\n"          if defined $self->{_network};
    print "address: $self->{_address}\n"          if defined $self->{_address};
    print "port: $self->{_port}\n"                if defined $self->{_port};
    print "protocol: $self->{_protocol}\n"        if defined $self->{_protocol};
    print "src-mac: $self->{_src_mac}\n"          if defined $self->{_src_mac};

    return 0;
}

sub rule {
    my ($self) = @_;
    my $rule = "";
    my $can_use_port = 1;

    my $addr_checker;
    my $prefix_checker;
    my $pure_addr_checker;
    my $ip_term;
    my $prefix_term;

    if ($self->{_ip_version} eq "ipv4") {
        # This is an IPv4 rule
        $addr_checker = 'ipv4_negate';
        $prefix_checker = 'ipv4net_negate';
        $pure_addr_checker = 'ipv4';
        $ip_term = "IPv4";
        $prefix_term = "subnet";
    } elsif ($self->{_ip_version} eq "ipv6") {
        # This is an IPv6 rule
        $addr_checker = 'ipv6_negate';
        $prefix_checker = 'ipv6net_negate';
        $pure_addr_checker = 'ipv6';
        $ip_term = "IPv6";
        $prefix_term = "prefix";
    } else {
        return (undef, "Invalid IP version: $self->{_ip_version}");
    }

    if (   !defined($self->{_protocol})
        || !defined($_protocolswithports{$self->{_protocol}}))
    {
        $can_use_port = 0;
    }

    if (($self->{_srcdst} eq "source") && (defined($self->{_src_mac}))) {

        # handle src mac
        my $str = $self->{_src_mac};
        my $negate = '';
        if ($str =~ /^\!(.*)$/) {
            $str = $1;
            $negate = '! ';
        }
        $rule .= "-m mac $negate --mac-source $str ";
    }

    my %group_ok;
    foreach my $group_type ('address', 'network', 'port') {
        $group_ok{$group_type} = 1;
    }

    # set the address filter parameters
    if (defined($self->{_network})) {
        my $str = $self->{_network};
        return (undef, "\"$str\" is not a valid $ip_term $prefix_term")
            if (!Vyatta::TypeChecker::validateType($prefix_checker, $str, 1));
        my $negate = '';
        if ($str =~ /^\!(.*)$/) {
            $str = $1;
            $negate = '! ';
        }
        $rule .= "$negate --$self->{_srcdst} $str ";
        $group_ok{network} = 0;
    } elsif (defined($self->{_address})) {
        my $str = $self->{_address};
        return (undef, "\"$str\" is not a valid $ip_term address")
            if (!Vyatta::TypeChecker::validateType($addr_checker, $str, 1));
        my $negate = '';
        if ($str =~ /^\!(.*)$/) {
            $str = $1;
            $negate = '! ';
        }
        $rule .= "$negate --$self->{_srcdst} $str ";
        $group_ok{address} = 0;
    } elsif ((defined $self->{_range_start}) && (defined $self->{_range_stop})) {
        my $start = $self->{_range_start};
        my $stop = $self->{_range_stop};
        return (undef, "\"$start-$stop\" is not a valid IP range")
            if (   !Vyatta::TypeChecker::validateType($addr_checker, $start, 1)
                || !Vyatta::TypeChecker::validateType($pure_addr_checker, $stop, 1));
        my $negate = '';
        if ($self->{_range_start} =~ /^!(.*)$/) {
            $start  = $1;
            $negate = '! ';
        }
        if ("$self->{_srcdst}" eq "source") {
            $rule .= ("-m iprange $negate --src-range $start-$self->{_range_stop} ");
        }elsif ("$self->{_srcdst}" eq "destination") {
            $rule .= ("-m iprange $negate --dst-range $start-$self->{_range_stop} ");
        }
        $group_ok{address} = 0;
        $group_ok{network} = 0;
    }

    $group_ok{port} = 0 if defined $self->{_port};
    my ($port_str, $port_err)= getPortRuleString($self->{_port}, $can_use_port,($self->{_srcdst} eq "source") ? "s" : "d",$self->{_protocol});
    return (undef, $port_err) if (!defined($port_str));
    $rule .= $port_str;
    # Handle groups last so we can check $group_ok
    my %group_used = ('address' => 0, 'network' => 0);
    foreach my $group_type ('address', 'network', 'port') {
        my $var_name = '_' . $group_type . '_group';
        if (defined($self->{$var_name})) {
            $group_used{$group_type} = 1;
            my $name = $self->{$var_name};
            if (!$group_ok{$group_type}) {
                return (undef, "Can't mix $self->{_srcdst} $group_type group [$name] and $group_type");
            }
            my $group = new Vyatta::IpTables::IpSet($name, $group_type);
            my ($set_rule, $err_str) = $group->rule($self->{_srcdst});
            return ($err_str,) if !defined $set_rule;
            $rule .= $set_rule;
        }
    }
    if ($group_used{address} and $group_used{network}) {
        return (undef,"Can't combine network and address group for $self->{_srcdst}\n");
    }
    return ($rule, undef);
}

sub outputXmlElem {
    my ($name, $value, $fh) = @_;
    return if !defined $value;
    print $fh "    <$name>$value</$name>\n";
}

sub outputXml {
    my ($self, $prefix, $fh) = @_;
    if (   !defined($self->{_address})
        && !defined($self->{_network})
        && !defined($self->{_range_start})
        && !defined($self->{_range_stop}))
    {
        if (($self->{_ip_version} eq "ipv4")) {
            $self->{_address} = "0.0.0.0/0";
        } else {
            $self->{_address} = "::/0";
        }
    }
    outputXmlElem("${prefix}_addr", $self->{_address}, $fh);
    outputXmlElem("${prefix}_net", $self->{_network}, $fh);
    outputXmlElem("${prefix}_addr_start", $self->{_range_start}, $fh);
    outputXmlElem("${prefix}_addr_stop", $self->{_range_stop}, $fh);
    outputXmlElem("${prefix}_port", $self->{_port}, $fh);
}

1;
