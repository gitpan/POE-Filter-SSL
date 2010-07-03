package POE::Filter::SSL;

use strict;
use POE::Filter;
use Net::SSLeay;

use vars qw($VERSION @ISA);
$VERSION = '0.12';
@ISA = qw(POE::Filter);

our $globalinfos;
my $debug = 0;

BEGIN {
   eval {
      require Net::SSLeay;
      Net::SSLeay->import( 1.30 );
   };
   Net::SSLeay::load_error_strings();
   Net::SSLeay::SSLeay_add_ssl_algorithms();
   Net::SSLeay::randomize();
}

require XSLoader;
XSLoader::load('POE::Filter::SSL', $VERSION);

sub new {
   my $type = shift;
   my $params = {@_};
   my $self = bless({}, $type);
   $self->{buffer} = '';
   $self->{debug} = $params->{debug} || 0;
   $self->{cacrl} = $params->{cacrl} || undef;
   $self->{client} = $params->{client} || 0;

   $self->{context} = Net::SSLeay::CTX_new();

   Net::SSLeay::CTX_use_RSAPrivateKey_file($self->{context}, $params->{key}, &Net::SSLeay::FILETYPE_PEM);
   Net::SSLeay::CTX_use_certificate_file($self->{context}, $params->{crt}, &Net::SSLeay::FILETYPE_PEM);
   if ($params->{cacrt}) {
      Net::SSLeay::CTX_load_verify_locations($self->{context}, $params->{cactr}, '');
      Net::SSLeay::CTX_set_client_CA_list($self->{context}, Net::SSLeay::load_client_CA_file($params->{cacrt}));
      Net::SSLeay::CTX_set_verify_depth($self->{context}, 5);
   }

   if ($params->{cipher}) {
      Net::SSLeay::CTX_set_cipher_list($self->{context}, $params->{cipher});
   }

   $self->{rbio} = Net::SSLeay::BIO_new(Net::SSLeay::BIO_s_mem())
      or die("Create rBIO_s_mem(): ".$!);
   $self->{wbio} = Net::SSLeay::BIO_new(Net::SSLeay::BIO_s_mem())
      or die("Create wBIO_s_mem(): ".$!);
   $self->{ssl} = Net::SSLeay::new($self->{context});
   Net::SSLeay::set_bio($self->{ssl}, $self->{rbio}, $self->{wbio});

   if ($params->{clientcert}) {
      my $orfilter = &Net::SSLeay::VERIFY_PEER
                   | &Net::SSLeay::VERIFY_CLIENT_ONCE;
      $orfilter |=  &Net::SSLeay::VERIFY_FAIL_IF_NO_PEER_CERT
         if $params->{blockbadclientcert};
      Net::SSLeay::set_verify($self->{ssl}, $orfilter, \&VERIFY);
   }
   
   $globalinfos = [0, 0, []];

   $self
}

sub VERIFY {
   my ($ok, $x509_store_ctx) = @_;
   print "VERIFY!\n" if $debug;
   $globalinfos->[0] = $ok ? 1 : 2 if ($globalinfos->[0] != 2);
   $globalinfos->[1]++;
   if (my $x = Net::SSLeay::X509_STORE_CTX_get_current_cert($x509_store_ctx)) {
      push(@{$globalinfos->[2]},[Net::SSLeay::X509_NAME_oneline(Net::SSLeay::X509_get_subject_name($x)),
                                 Net::SSLeay::X509_NAME_oneline(Net::SSLeay::X509_get_issuer_name($x)),
                                 X509_get_serialNumber($x)]);
   }
   return 1; # $ok; # 1=accept cert, 0=reject
}

sub clone {
   my $self = shift;
   my $buffer = '';
   my $clone = bless \$buffer, ref $self;
}

sub get_one_start {
   my ($self, $data) = @_;
   print "GETONESTART: NETWORK -> SSL -> POE: ".hexdump(join("", @$data))."\n" if $debug;
   $self->writeToSSLBIO(join("", @$data), $self->{accepted} ? 0 : 1);
   []
}

sub get_one {
   my $self = shift;
   print "GETONE: BEGIN\n" if $debug;
   my @return = ();
   push(@return, '') if ($self->doSSL() || $self->{buffer});
   my $data = Net::SSLeay::read($self->{ssl});
   push(@return, $data) if $data;
   [@return]
}

sub get {
   print "GET: BEGIN\n" if $debug;
   my ($self, $chunks) = @_;
   my @return = ();
   #print "GET:\n" if $debug;
   push(@return, '') if ($self->doSSL() || $self->{buffer});
   foreach my $data (@$chunks) {
      print "GET: NETWORK -> SSL -> POE: ".join("", @$data)."\n" if $debug;
      $self->writeToSSLBIO(join("", @$data));
      my $data = Net::SSLeay::read($self->{ssl});
      print "GET: Read ".length($data)." bytes.\n" if $debug;
      push(@return, $data);
   }
   [@return]
}

sub put {
   my ($self, $chunks) = @_;
   print "PUT: BEGIN\n" if $debug;
   my @return = ();
   $self->doSSL();
   if ($self->{accepted}) {
      if (defined($self->{sendbuf})) {
         foreach my $cdata (@{$self->{sendbuf}}) {
            $self->writeToSSL($cdata);
         }
         delete($self->{sendbuf});
      }
   }
   foreach my $data (@$chunks) {
      print "PUT: POE -> SSL -> NETWORK: ".$data."\r\n" if $debug;
      if ($self->{accepted}) {
         $self->writeToSSL($data);
      } else {
         push(@{$self->{sendbuf}}, $data) if ($data);
      }
   }
   push(@return, $self->{buffer}) if $self->{buffer};
   $self->{buffer} = '';
   [@return]
}

sub writeToSSL {
   my $self = shift;
   my $data = shift;
   if ((my $sent = Net::SSLeay::write($self->{ssl}, $data)) != length($data)) {
      my $err2 = Net::SSLeay::get_error($self->{ssl}, $sent);
      die("PUT: Not all data given to SSL(".$err2."): ".$sent." != ".length($data)) if ($sent);
   }
   $self->doSSL();
}

sub writeToSSLBIO {
   my $self = shift;
   my $data = shift;
   my $nodoSSL = shift;
   if ((my $sent = Net::SSLeay::BIO_write($self->{rbio}, $data)) != length($data)) {
      my $err2 = Net::SSLeay::get_error($self->{ssl}, $sent);
      die("GET: Not all data given to BIO SSL(".$err2."): ".$sent." != ".length($data)) if ($sent);
   }
   $self->doSSL() unless $nodoSSL;
}


sub get_pending {
  my $self = shift;
  #print "get_pending\n" if $debug;
  #return [ $self->{buffer} ] if length $self->{buffer};
  return undef;
}

sub doSSL {
   my $self = shift;
   my $ret = 0;
   print "SSLing..." if $debug;
   unless ($self->{accepted}) {
      my $err = $self->{client} ?
         Net::SSLeay::connect($self->{ssl}) :
         Net::SSLeay::accept($self->{ssl});
      if ($err == 1) {
         $self->{infos} = [((@$globalinfos)[0..2])];
         $globalinfos = [0, 0, []];
         $self->{accepted}++;
         $ret++;
      } else {
         my $err2 = Net::SSLeay::get_error($self->{ssl}, $err);
         unless ($err2 == Net::SSLeay::ERROR_WANT_READ()) {
            die("ERROR: ERR1:".$err." ERR2:".$err2." HINT: In server mode:".
                " Check if you have configured a CRT and KEY file, and that ".
                "both are readable.") unless ($err2 == 5); # SSL_ERROR_SYSCALL
         }
      }
   }
   my $data = Net::SSLeay::BIO_read($self->{wbio});
   $self->{buffer} .= $data if ($data);
   print $ret."\n" if $debug;
   return $ret;
}

sub clientCertExists {
   my $self = shift;
   return ((ref($self->{infos}) eq "ARRAY") && ($self->{infos}->[1]));
}

sub clientCertValid {
   my $self = shift;
   my $valid = 1;
   if (defined($self->{cacrl})) {
      $valid = $self->clientCertNotOnCRL($self->{cacrl}) ? 1 : 0;
   }
   return $self->clientCertExists() ? (@{$self->{infos}->[2]} && $valid) : undef;
}

sub clientCertIds {
   my $self = shift;
   return $self->clientCertExists ? @{$self->{infos}->[2]} : undef;
}

sub clientCertNotOnCRL {
   my $self = shift;
   my $crlfilename = shift;
   my @certids = $self->clientCertIds();
   if (scalar(@certids)) {
      my $found = 0;
      my $badcrls = 0;
      my $jump = 0;
      print("----- SSL Infos BEGIN ---------------"."\n") if $self->{debug};
      foreach (@{$self->{infos}->[2]}) {
         my $crlstatus = verify_serial_against_crl_file($crlfilename, $_->[2]);
         $badcrls++ if $crlstatus;
         $crlstatus = $crlstatus ? "INVALID (".($crlstatus !~ m,^CRL:, ? hexdump($crlstatus) : $crlstatus).")" : "VALID";
         my $t = ("  " x $jump++);
         if (ref($_) eq "ARRAY") {
            if ($self->{debug}){
               print(" ".$t."  |---[ Subcertificate ]---\n") if $t;
               print(" ".$t."  | Subject Name: ".$_->[0]."\n");
               print(" ".$t."  | Issuer Name : ".$_->[1]."\n");
               print(" ".$t."  | Serial      : ".hexdump($_->[2])."\n");
               print(" ".$t."  | CRL Status  : ".$crlstatus."\n");
            }
         } else {
            print(" NOCERTINFOS!"."\n") if $self->{debug};
            return 0;
         }
      }
      print("----- SSL Infos END -----------------"."\n") if $self->{debug};
      return 1 unless $badcrls;
   }
   return 0;
}

sub handshakeDone {
   my $self = shift;
   my $params = {@_};
   return ($self->{accepted} && (($params->{ignorebuf}) || ((!$self->{sendbuf}) && (!$self->{buffer})))) || 0;
}

sub DESTROY {
   my $self = shift;
   Net::SSLeay::free($self->{ssl})
      if $self->{ssl};
   Net::SSLeay::CTX_free($self->{context})
      if $self->{context};
   #Net::SSLeay::BIO_free($self->{bio}) # CTX_free automatically frees BIO!!!
   #   if $self->{bio};
}

sub hexdump { join ':', map { sprintf "%02X", $_ } unpack "C*", $_[0]; }

1;

__END__

=head1 NAME

POE::Filter::SSL - The easiest and flexiblest way to SSL in POE!

=head1 VERSION

Version 0.11

=head1 DESCRIPTION

This module allows to secure connections of POE::Wheel::ReadWrite with OpenSSL by a
POE::Filter object, and behaves beside of SSL as POE::Filter::Stream.

POE::Filter::SSL can be added, switched and removed during runtime, for example if you
want to initiate SSL (e.g. STARTTLS) on an established connection. You also can combine
POE::Filter::SSL with other filters, for example have an HTTPS server together
with POE::Filter::HTTPD (see I<ADVANCED EXAMPLE> later on this site).

POE::Filter::SSL is based on Net::SSLeay, but got own XS calls Net::SSLeay is missing.

=over 4

=item B<Features>

=over 2

Full non-blocking processing

No use of sockets at all

Server and client mode

Optional client certificate verification

Allows to accept connections with invalid or missing client certificate and return custom error data

CRL check of client certificates

Retrieve client certificate details (subject name, issuer name, certificate serial)

=back

=back

=over 4

=item B<Upcoming Features>

=over 2

Direct cipher encryption without SSL or TLS protocol, for example with static AES encryption

=back

=back

=head1 SYNOPSIS

POE::Filter::SSL acts as default as a SSL server, to switch to client mode you have to set the I<client> option of new().

=over 2

=item Client

  #!perl

  use warnings;
  use strict;

  use POE qw(Component::Client::TCP Filter::SSL);

  POE::Component::Client::TCP->new(
    RemoteAddress => "yahoo.com",
    RemotePort    => 443,
    Filter        => [ "POE::Filter::SSL", client => 1 ],    ## HERE WE ARE!
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

=item Server

  #!perl

  use warnings;
  use strict;

  use POE qw(Component::Server::TCP);

  POE::Component::Server::TCP->new(
    Port => 443,
    ClientFilter => [ "POE::Filter::SSL", crt => 'server.crt', key => 'server.key' ],
    ClientConnected => sub {
      print "got a connection from $_[HEAP]{remote_ip}\n";
      $_[HEAP]{client}->put("Smile from the server!");
    },
    ClientInput => sub {
      my $client_input = $_[ARG0];
      # The following line is needed to do the SSL handshake!
      return $_[HEAP]{client}->put() unless $client_input;
      $client_input =~ tr[a-zA-Z][n-za-mN-ZA-M];
      $_[HEAP]{client}->put($client_input);
    },
  );

  POE::Kernel->run;
  exit;

=back

=head1 FUNCTIONS

=over 4

=item B<new(options)>

Returns a new B<POE::Filter::SSL> object. It accepts the following options:

=over 2

=item debug

Get debug messages, currently mainly used by I<clientCertNotOnCRL()>.

=item client

The filter has to behave as a SSL client, not as a SSL server. 

=item crt

The certificate file (.crt) for the server.

=item key

The key file (.key) of the certificate for the server.

=item clientcert

The server requests the client for a client certificat during ssl handshake.

B<WARNING:> If the client provides an untrusted or no client certficate, the connection is B<not> failing. You have to ask clientCertValid() if the certicate is valid!

=item cacrt

The ca certificate file (ca.crt), which is used to verificated the client certificates against a CA.

=item cacrl

Configures a CRL against the client certificate is proofed by I<clientCertValid()>.

=item cipher

Specify which ciphers are allowed for the synchronous encrypted transfer of the data over the ssl connection.

Example:

   cipher => 'AES256-SHA'

=item blockbadclientcert

Let OpenSSL deny the connection if there is no or an invalid client certificate. You will never get data from the client, nor can you send it an error message this was.

B<WARNING:> If the client is listed in the CRL file, the connection will be established! You have to ask I<clientCertValid()> if you have the I<crl> option on I<new()> has been set, otherwise I<clientCertNotOnCRL()> if the certificate is listed on CRL!

=back

=item handshakeDone(options)

Returns I<true> if the handshake is done and all data for hanshake has been written out. It accepts the following options:

=over 2

=item ignorebuf

Returns I<true> if OpenSSL has established the connection, regardless if all data has been written out. This is needed if you want to exchange the Filter of POE::Wheel::ReadWrite before the first data comes in (see I<ADVANCED EXAMPLE> later on this site).

=back

=item clientCertNotOnCRL($file)

Verifies if the serial of the client certificate is not contained in the CRL $file. No file caching is done, each call opens the file again.

B<WARNING:> If your CRL file is missing, can not be opened is empty or has no blocked certificate at all in it, then every call will get blocked!

=item clientCertIds()

Returns an array of every certificate found by OpenSSL. Each element
is again a array. The first element is the value of I<X509_get_subject_name>,
second is the value of I<X509_get_issuer_name> and third element is the
serial of the certificate in binary form. You have to use I<split()> and
I<ord()>, or the I<hexdump()> function, to convert it to a readable form.

Example:

   my ($certid) = ($heap->{sslfilter}->clientCertIds());
   $certid = $certid ? $certid->[0]."<br>".$certid->[1]."<br>SERIAL=".hexdump($certid->[2]) : 'No client certificate';

=item clientCertValid()

Returns I<true> if there is a client certificate that is valid. It
also tests against the crl, if you have the I<cacrl> option set on I<new()>.

=item clientCertExists()

Returns I<true> if there is a client certificate, that maybe is untrusted.

B<WARNING:> If the client provides an untrusted client certficate a client certicate that is listed in CRL, this function maybe return I<true>. You have to ask I<clientCertValid()> if the certicate is valid!

=item hexdump($string)

Returns string data in hex format.

Example:

  perl -e 'use POE::Filter::SSL; print POE::Filter::SSL::hexdump("test")."\n";'
  74:65:73:74

=back

=head2 Internal functions and POE::Filter handler

=over 2

=item VERIFY()

=item X509_get_serialNumber()

=item clone()

=item doSSL()

=item get()

=item get_one()

=item get_one_start()

=item get_pending()

=item writeToSSLBIO()

=item writeToSSL()

=item put()

=item verify_serial_against_crl_file()

=back

=head1 ADVANCED EXAMPLE

The following example implements a HTTPS server with client certificate verification, which shows details about the verified client certificate. If you uncomment the POE::Filter::HTTPD block, it also shows the URI property of the parsed HTTP::Response object from POE::Filter::HTTPD.

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
                  clientcert => 1
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
              $certid = $certid ? $certid->[0]."<br>".$certid->[1]."<br>SERIAL=".hexdump($certid->[2]) : 'No client certificate';
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

=head1 AUTHOR

Markus Mueller, C<< <privi at cpan.org> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-poe-filter-ssl at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=POE-Filter-SSL>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc POE::Filter::SSL

You can also look for information at:

=over 4

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=POE-Filter-SSL>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/POE-Filter-SSL>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/POE-Filter-SSL>

=item * Search CPAN

L<http://search.cpan.org/dist/POE-Filter-SSL>

=back

=head1 Commercial support

Commercial support can be gained at <sslsupport at priv.de>

=head1 COPYRIGHT & LICENSE

Copyright 2010 Markus Mueller, all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut

1; # End of POE::Filter::SSL
