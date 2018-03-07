#!/usr/local/bin/perl -w
#------------------------------------------------------------------------------
# Licensed Materials - Property of IBM (C) Copyright IBM Corp. 2010, 2010
# All Rights Reserved US Government Users Restricted Rights - Use, duplication
# or disclosure restricted by GSA ADP Schedule Contract with IBM Corp
#------------------------------------------------------------------------------

#  perl itm_net.pl
#
#  A cronjob to check for netstat -an problems
#  It is expected to be run periodically via crontab
#  on a Linux or AIX system. In cases where any ITM
#  related ports are experiencing Send_q higher then
#  8191 bytes, an email is sent.
#
#  Options:
#           -test   name a test file instead of running netstat -an
#           -o      name an output file, default /tmp/itm_net.txt
#           -email  name an email recipient
#
#
#  john alvord, IBM Corporation, 27 February 2018
#  jalvord@us.ibm.com
#
# tested on Windows Activestate 5.20.2
# test on zLinux and AIX
#
#    # remember debug breakpoint
# $DB::single=2;   # remember debug breakpoint

#use warnings::unused; # debug used to check for unused variables
use strict;
use warnings;
use Cwd;
my $cwd = getcwd;
use Data::Dumper;               # debug only

# See short history at end of module

my $gVersion = "1.00000";
my $gWin = (-e "C://") ? 1 : 0;    # 1=Windows, 0=Linux/Unix



my $opt_o;
my $opt_port;
my $opt_test;
my $opt_email;

while (@ARGV) {
   if ($ARGV[0] eq "-o") {
      shift(@ARGV);
      $opt_o = shift(@ARGV);
      die if !defined $opt_o;
   } elsif ($ARGV[0] eq "-test") {
      shift(@ARGV);
      $opt_test = shift(@ARGV);
      die if !defined $opt_test;
   } elsif ($ARGV[0] eq "-port") {
      shift(@ARGV);
      $opt_port = shift(@ARGV);
      die if !defined $opt_port;
   } elsif ($ARGV[0] eq "-email") {
      shift(@ARGV);
      $opt_email = shift(@ARGV);
      die if !defined $opt_email;
   } else {
     die "unknown argument $ARGV[0]";
   }
}

$opt_o = "itm_net.txt" if !defined $opt_o;
$opt_port = "" if !defined $opt_port;
$opt_test = "" if !defined $opt_test;
$opt_email = 'jalvord@us.ibm.com' if !defined $opt_email;

if ($opt_test eq "") {
   die "itm_net.pl runs on Linux and Unix only" if $gWin == 1;
}

my $descr_line = "";
my @nzero_line;
my %nzero_ports = (
                     '1918' => 1,
                     '3660' => 1,
                     '63358' => 1,
                     '65100' => 1,
                  );

$nzero_ports{$opt_port} = 1 if defined $opt_port;


my %inbound;
my $inbound_ref;

#         $rc = system($cmd);

my $netstatfn = "/tmp/netstat.info";
my $cmd;
my $rc;
if ($opt_test eq "") {
   $cmd = "netstat -an > /tmp/netstat.info";
   $rc = system($cmd);
   die "netstat failed rc=$rc" if $rc != 0;
   $netstatfn = "/tmp/netstat.info";
} else {
   $netstatfn = $opt_test;
}


open NETS,"< $netstatfn" or die " open netstat.info file $netstatfn -  $!";
my @nts = <NETS>;
close NETS;

# sample netstat outputs

# Active Internet connections (including servers)
# PCB/ADDR         Proto Recv-Q Send-Q  Local Address      Foreign Address    (state)
# f1000e000ca7cbb8 tcp4       0      0  *.*                   *.*                   CLOSED
# f1000e0000ac93b8 tcp4       0      0  *.*                   *.*                   CLOSED
# f1000e00003303b8 tcp4       0      0  *.*                   *.*                   CLOSED
# f1000e00005bcbb8 tcp        0      0  *.*                   *.*                   CLOSED
# f1000e00005bdbb8 tcp4       0      0  *.*                   *.*                   CLOSED
# f1000e00005b9bb8 tcp6       0      0  *.22                  *.*                   LISTEN
# ...
# Active UNIX domain sockets
# Active Internet connections (servers and established)
#
# Active Internet connections (servers and established)
# Proto Recv-Q Send-Q Local Address               Foreign Address             State       PID/Program name
# tcp        0      0 0.0.0.0:1920                0.0.0.0:*                   LISTEN      18382/klzagent
# tcp        0      0 0.0.0.0:34272               0.0.0.0:*                   LISTEN      18382/klzagent
# tcp        0      0 0.0.0.0:28002               0.0.0.0:*                   LISTEN      5955/avagent.bin
# ...
# Active UNIX domain sockets (servers and established)

my $active_line = "";
my $max_sendq = 0;
my $max_recvq = 0;
my $total_sendq = 0;
my $total_recvq = 0;

my $l = 0;
my $netstat_state = 0;                 # seaching for "Active Internet connections"
my $recvq_pos = -1;
my $sendq_pos = -1;
foreach my $oneline (@nts) {
   $l++;
   chomp($oneline);
   if ($netstat_state == 0) {           # seaching for "Active Internet connections"
      next if substr($oneline,0,27) ne "Active Internet connections";
      $active_line = $oneline;
      $netstat_state = 1;
   } elsif ($netstat_state == 1) {           # next line is column descriptor line
      $recvq_pos = index($oneline,"Recv-Q");
      $sendq_pos = index($oneline,"Send-Q");
      $descr_line = $oneline;
      $netstat_state = 2;
   } elsif ($netstat_state == 2) {           # collect non-zero send/recv queues
      last if index($oneline,"Active UNIX domain sockets") != -1;
      $oneline =~ /(tcp\S*)\s*(\d+)\s*(\d+)\s*(\S+)\s*(\S+)/;
      my $proto = $1;
      if (defined $proto) {
         my $recvq = $2;
         my $sendq = $3;
         my $localad = $4;
         my $foreignad = $5;
         my $localport = "";
         my $foreignport = "";
         my $localsystem = "";
         my $foreignsystem = "";
         $localad =~ /(\S+)[:\.](\S+)/;
         $localsystem = $1 if defined $1;
         $localport = $2 if defined $2;
         $foreignad =~ /(\S+)[:\.](\S+)/;
         $foreignsystem = $1 if defined $1;
         $foreignport = $2 if defined $2;
         if ((defined $nzero_ports{$localport}) or (defined $nzero_ports{$foreignport})) {
            if (defined $recvq) {
               if (defined $sendq) {
                  if (($recvq > 0) or ($sendq > 0)) {
                     next if ($recvq == 0) and ($sendq == 0);
                     push @nzero_line,$oneline;
                     $total_sendq += 1;
                     $total_recvq += 1;
                     $max_sendq = $sendq if $sendq > $max_sendq;
                     $max_recvq = $recvq if $recvq > $max_recvq;
                  }
               }
            }
         }
         if (defined $nzero_ports{$localport}) {
            $inbound_ref = $inbound{$localport};
            if (!defined $inbound_ref) {
               my %inboundref = (
                                   instances => {},
                                   count => 0,
                                );
               $inbound_ref = \%inboundref;
               $inbound{$localport} = \%inboundref;
            }
            $inbound_ref->{count} += 1;
            $inbound_ref->{instances}{$foreignsystem} += 1;
         }
      }
   }
}

if ($max_sendq > 8191) {

   my $hostname = `hostname`;
   chomp $hostname;

   my $uname = `uname`;
   chomp $uname;

   my $stamp = `date`;
   chomp $stamp;

   open NETO,">$opt_o" or die " open output file $opt_o failed -  $!";
   my $outl;
   my $ol = 0;

   print NETO "Netstat -an TCP Recv-Q and Send-Q high counts\n";
   for my $r (@nzero_line) {
      print NETO "$r\n";
   }
   close NETO;

   my $pmrline = "On $hostname at $stamp - Max Send-Q[$max_sendq] Max Recv-Q[$max_recvq]";
   if ($opt_email ne "") {
      if ($gWin == 0) {
         my $cmd_email = $opt_email;
         $cmd_email =~ s/\@/\\\@/g;
         $cmd = "(echo $pmrline && uuencode  $opt_o  $opt_o) | mailx -s tcp-blocking " . $cmd_email if $uname eq "AIX";
         $cmd = "(echo $pmrline && uuencode  $opt_o  $opt_o) | mail -s tcp-blocking " . $cmd_email if $uname eq "Linux";
         $rc = system($cmd);
      }
   }
}

exit 0;

