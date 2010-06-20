#!perl

use strict;
use warnings;
use Socket;
use POE qw(
   Wheel::SocketFactory
   Wheel::ReadWrite
   Driver::SysRW
   Filter::SSL
   Filter::Stackable
   Filter::HTTPD
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
                     Filter     => POE::Filter::SSL->new(           ### HERE WE ARE!!!
                        crt    => 'server.crt',
                        key    => 'server.key',
                        cactr  => 'ca.crt',
                        cipher => 'AES256-SHA',
                        cacrl  => 'ca.crl',
                        debug  => 1,
                        clientcertrequest => 1
                     ),
                     InputEvent => 'socket_input',
                     ErrorEvent => '_stop',
                  );
                  $heap->{sslfilter} = $heap->{socket_wheel}->get_input_filter();
               },
               socket_input => sub {
                  my ($kernel, $heap, $buf) = @_[KERNEL, HEAP, ARG0];
                  ### Uncomment the follwing lines if you want to use POE::Filter::HTTPD after the SSL handshake
                  #if (ref($heap->{socket_wheel}->get_input_filter()) eq "POE::Filter::SSL") {
                  #   if ($heap->{sslfilter}->handshakeDone(ignorebuf => 1)) {
                  #      $heap->{socket_wheel}->set_input_filter(POE::Filter::Stackable->new(
                  #         Filters => [
                  #            $heap->{sslfilter},
                  #            POE::Filter::HTTPD->new()
                  #         ])
                  #      );
                  #   }
                  #}
                  # This following line is needed to do the SSL handshake!
                  return $heap->{socket_wheel}->put()
                     unless $heap->{sslfilter}->handshakeDone();
                  my ($certid) = ($heap->{sslfilter}->clientCertIds());
                  $certid = $certid ? $certid->[0]."<br>".$certid->[1]."<br>SERIAL=".ord($certid->[2]) : 'No client certificate';
                  my $content = "HTTP/1.0 OK\r\nContent-type: text/html\r\n\r\n";
                  if ($heap->{sslfilter}->clientCertValid()) {
                     $content .= "Hello <font color=green>valid</font> client Certifcate:";
                  } else {
                     $content .= "None or <font color=red>invalid</font> client certificate:";
                  }
                  $content .= "<hr>".$certid."<hr>";
                  $content .= "Your URL was: ".$buf->uri."<hr>" # This line will only appear if you uncomment the lines above!
                     if (ref($buf) eq "HTTP::Request");
                  $content .= localtime(time());
                  $heap->{socket_wheel}->put($content);
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

