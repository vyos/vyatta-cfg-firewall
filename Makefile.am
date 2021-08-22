cfgdir = $(datadir)/vyatta-cfg/templates
share_perl5dir = /opt/vyatta/share/perl5/Vyatta/IpTables
curverdir = $(sysconfdir)/config-migrate/current
modprobedir = /etc/modprobe.d

modprobe_DATA = etc/modprobe.d/vyatta_xt_recent.conf
modprobe_DATA += etc/modprobe.d/vyatta_ipset.conf

sbin_SCRIPTS =
curver_DATA = cfg-version/firewall@6

sbin_SCRIPTS += scripts/firewall/vyatta-firewall.pl
sbin_SCRIPTS += scripts/firewall/vyatta-firewall-trap.pl
sbin_SCRIPTS += scripts/firewall/firewall.init
sbin_SCRIPTS += scripts/firewall/vyatta-ipset.pl
sbin_SCRIPTS += scripts/firewall/vyatta-fw-global-state-policy.pl
sbin_SCRIPTS += scripts/firewall/valid_port_range.pl

share_perl5_DATA  = lib/Vyatta/IpTables/Rule.pm
share_perl5_DATA += lib/Vyatta/IpTables/AddressFilter.pm
share_perl5_DATA += lib/Vyatta/IpTables/IpSet.pm
share_perl5_DATA += lib/Vyatta/IpTables/Mgr.pm

cpiop = find  . ! -regex '\(.*~\|.*\.bak\|.*\.swp\|.*\#.*\#\)' -print0 | \
  cpio -0pdu


all-local:
	./gen-interface-templates.pl
	./gen-interface-policy-templates.pl

clean-local:
	rm -rf generated-templates

install-exec-hook:
	mkdir -p $(DESTDIR)$(cfgdir)
	cd templates; $(cpiop) $(DESTDIR)$(cfgdir); cd ..
	cd generated-templates; $(cpiop) $(DESTDIR)$(cfgdir); cd ..
