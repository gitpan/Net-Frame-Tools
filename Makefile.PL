#
# $Id: Makefile.PL 316 2010-06-03 13:37:26Z gomor $
#
use ExtUtils::MakeMaker;

require v5.6.1;

WriteMakefile(
   NAME          => 'Net::Frame::Tools',
   VERSION_FROM  => 'lib/Net/Frame/Tools.pm',
   ABSTRACT_FROM => 'lib/Net/Frame/Tools.pm',
   LICENSE       => 'artistic',
   AUTHOR        => 'GomoR <gomor-cpan_at_gomor.org>',
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
