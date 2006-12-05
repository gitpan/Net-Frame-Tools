#
# $Id: Makefile.PL,v 1.4 2006/12/05 20:39:27 gomor Exp $
#
use ExtUtils::MakeMaker;

WriteMakefile(
   NAME          => 'Net::Frame::Tools',
   VERSION_FROM  => 'lib/Net/Frame/Tools.pm',
   ABSTRACT_FROM => 'lib/Net/Frame/Tools.pm',
   LICENSE       => 'Artistic',
   AUTHOR        => 'GomoR <perl@gomor.org>',
   EXE_FILES     => [ @{[glob('bin/*.pl')]} ],
   PREREQ_PM => {
      Net::Write         => '1.00',
      Net::Frame         => 0,
      Net::Frame::Simple => 0,
      Net::Frame::Dump   => 0,
      Net::Frame::Device => 0,
      Net::Netmask       => 0,
      Term::ReadLine     => 0,
   },
);
