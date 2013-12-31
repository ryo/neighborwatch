#!/usr/local/bin/perl

# Reference:
#   http://www.iana.org/assignments/ethernet-numbers     - Ethernet Numbers
#   http://standards.ieee.org/regauth/oui/oui.txt        - Vendor codes


while (<>) {
	push(@oui, $_);
}

$HEX = '[\da-fA-F]';

for (@oui) {
	chop;
	if (m/^\s+(${HEX}${HEX})-(${HEX}${HEX})-(${HEX}${HEX})\s+\(hex\)\s+(.*)/) {
		print "$1:$2:$3\t$4\n";
	}
}
