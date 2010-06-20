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

POE::Session->create(
   inline_states => {
      _start       => sub {
         my $heap = $_[HEAP];
         $heap->{listener} = POE::Wheel::SocketFactory->new(
            BindAddress  => '0.0.0.0',
            BindPort     => 443,
            Reuse        => 'yes',
            SuccessEvent => 'socket_birth',
            FailureEvent => '_stop',
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
                     Filter     => POE::Filter::SSL->new({crt => 'server.crt', key => 'server.key'}), ### HERE WE ARE!!!
                     InputEvent => 'socket_input',
                     ErrorEvent => '_stop',
                  );
               },
               socket_input => sub {
                  my ($kernel, $heap, $buf) = @_[KERNEL, HEAP, ARG0];
                  # This following line is needed to do the SSL handshake!
                  return $heap->{socket_wheel}->put()
                     unless $heap->{socket_wheel}->get_input_filter()->handshakeDone();
                  my $content = "HTTP/1.0 OK\r\nContent-type: text/html\r\n\r\n";
                  $content .= "Welcome on the SSL encrypted TCP connection!<br>\r\n";
                  $content .= localtime(time());
                  $heap->{socket_wheel}->put($content);
                  print "READ ".length($buf)." Bytes.\n";
                  $kernel->delay(_stop => 1);
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
