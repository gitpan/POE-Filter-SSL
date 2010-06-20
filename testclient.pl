#!perl

use warnings;
use strict;

use POE qw(Component::Client::TCP Filter::SSL);

POE::Component::Client::TCP->new(
  RemoteAddress => "yahoo.com",
  RemotePort    => 443,
  Filter => [
    "POE::Filter::SSL",              ## HERE WE ARE!
      client => 1 ],
  Connected     => sub {
    $_[HEAP]{server}->put("HEAD /\r\n");
  },
  ServerInput   => sub {
    my $input = $_[ARG0];
    # The following line is needed to do the SSL handshake!
    return $_[HEAP]{server}->put() unless $input;
    print "from server: $input\n";
  },
);

POE::Kernel->run();
exit;

