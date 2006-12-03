#
# $Id: Makefile.PL,v 1.2 2006/12/03 16:42:30 gomor Exp $
#
use ExtUtils::MakeMaker;

WriteMakefile(
   NAME      => 'Net::Frame::Tools',
   VERSION   => '1.00_01',
   LICENSE   => 'Artistic',
   PREREQ_PM => {
      Net::Write         => '1.00',
      Net::Frame         => 0,
      Net::Frame::Simple => 0,
      Net::Frame::Dump   => 0,
      Net::Frame::Device => 0,
      Term::ReadLine     => 0,
   },
   EXE_FILES => [ @{[glob('bin/*.pl')]} ],
   ABSTRACT  => 'small useful network utilities created using Net::Frame',
   AUTHOR    => 'GomoR <perl@gomor.org>',
);
