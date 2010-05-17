cfgdir = $(datadir)/vyatta-cfg/templates
share_perl5dir = /opt/vyatta/share/perl5/Vyatta/IpTables
curverdir = $(sysconfdir)/config-migrate/current
modprobedir = /etc/modprobe.d
modprobe_DATA = etc/modprobe.d/vyatta_nf_conntrack

sbin_SCRIPTS =
share_perl5_DATA =
curver_DATA = cfg-version/firewall@3

sbin_SCRIPTS += scripts/firewall/vyatta-firewall.pl
sbin_SCRIPTS += scripts/firewall/firewall.init
sbin_SCRIPTS += scripts/firewall/vyatta-ipset.pl

share_perl5_DATA  = lib/Vyatta/IpTables/Rule.pm
share_perl5_DATA += lib/Vyatta/IpTables/AddressFilter.pm
share_perl5_DATA += lib/Vyatta/IpTables/IpSet.pm

cpiop = find  . ! -regex '\(.*~\|.*\.bak\|.*\.swp\|.*\#.*\#\)' -print0 | \
  cpio -0pdu


all-local:
	./gen-interface-templates.pl

clean-local:
	rm -rf generated-templates

install-exec-hook:
	mkdir -p $(DESTDIR)$(cfgdir)
	cd templates; $(cpiop) $(DESTDIR)$(cfgdir); cd ..
	cd generated-templates; $(cpiop) $(DESTDIR)$(cfgdir); cd ..

