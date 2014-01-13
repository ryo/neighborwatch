#!/usr/local/bin/perl

# Reference:
#   http://www.iana.org/assignments/ethernet-numbers     - Ethernet Numbers
#   http://standards.ieee.org/regauth/oui/oui.txt        - Vendor codes

$H = qr/([\dA-F]{2})/;
while (<>) {
	print "$1:$2:$3\t$4\n" if (m/^\s+$H$H$H\s+\(base 16\)\s+(.*)/i);
}
