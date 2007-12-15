cfgdir = $(datadir)/vyatta-cfg/templates
share_perl5dir = /opt/vyatta/share/perl5

bin_SCRIPTS =
sbin_SCRIPTS =
sysconf_DATA =
share_perl5_DATA =

sbin_SCRIPTS += scripts/firewall/vyatta-firewall.pl
sbin_SCRIPTS += scripts/firewall/firewall.init

share_perl5_DATA += scripts/firewall/VyattaIpTablesAddressFilter.pm
share_perl5_DATA += scripts/firewall/VyattaIpTablesRule.pm


cpiop = find  . ! -regex '\(.*~\|.*\.bak\|.*\.swp\|.*\#.*\#\)' -print0 | \
  cpio -0pd

install-exec-hook:
	mkdir -p $(DESTDIR)$(cfgdir)
	cd templates; $(cpiop) $(DESTDIR)$(cfgdir)

