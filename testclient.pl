#!/usr/bin/perl

use strict;
use warnings;
use Socket;
use POE qw(
   Wheel::SocketFactory
   Wheel::ReadWrite
   Driver::SysRW
   Filter::SSL
);

my $host = "your.test.de";

POE::Session->create(
   inline_states => {
      _start       => sub {
         my $heap = $_[HEAP];
         $heap->{listener} = POE::Wheel::SocketFactory->new(
            RemoteAddress => $host,
            RemotePort    => 443,
            SuccessEvent => 'socket_birth',
            FailureEvent => 'socket_death',
         );
      },
      _stop => sub {
         delete $_[HEAP]->{listener};
      },
      socket_birth => sub {
         my ($socket) = $_[ARG0];
         POE::Session->create(
            inline_states => {
               _start       => sub {
                  my ($heap, $kernel, $connected_socket, $address, $port) = @_[HEAP, KERNEL, ARG0, ARG1, ARG2];
                  $heap->{socket_wheel} = POE::Wheel::ReadWrite->new(
                     Handle     => $connected_socket,
                     Driver     => POE::Driver::SysRW->new(),
                     Filter     => POE::Filter::SSL->new({client => 1}),            ### HERE WE ARE!!!
                     InputEvent => 'socket_input',
                     ErrorEvent => '_stop',
                  );
                  $heap->{socket_wheel}->put("GET / HTTP/1.0\r\nHost: ".$host."\r\n\r\n")
               },
               socket_input => sub {
                  my ($kernel, $heap, $buf) = @_[KERNEL, HEAP, ARG0];
                  # This following line is needed to do the SSL handshake!
                  return $heap->{socket_wheel}->put()
                     unless $heap->{socket_wheel}->get_input_filter()->handshakeDone();
                  print "Received: ".$buf."\n";
               },
               _stop => sub {
                  delete $_[HEAP]->{socket_wheel};
               }
            },
            args => [$socket],
         );
      }
   }
);

$poe_kernel->run();
