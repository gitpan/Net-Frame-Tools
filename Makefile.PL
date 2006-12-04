#
# $Id: Makefile.PL,v 1.3 2006/12/04 21:20:00 gomor Exp $
#
use ExtUtils::MakeMaker;

WriteMakefile(
   NAME      => 'Net::Frame::Tools',
   VERSION   => '1.00_02',
   ABSTRACT  => 'small useful network utilities created using Net::Frame',
   LICENSE   => 'Artistic',
   PREREQ_PM => {
      Net::Write         => '1.00',
      Net::Frame         => 0,
      Net::Frame::Simple => 0,
      Net::Frame::Dump   => 0,
      Net::Frame::Device => 0,
      Net::Netmask       => 0,
      Term::ReadLine     => 0,
   },
   EXE_FILES => [ @{[glob('bin/*.pl')]} ],
   AUTHOR    => 'GomoR <perl@gomor.org>',
);
