package POE::Filter::SSL;

use strict;
use POE::Filter;
use Net::SSLeay;

use vars qw($VERSION @ISA);
$VERSION = '0.01';
@ISA = qw(POE::Filter);

our $globalinfos;

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
   my $params = shift;
   my $self = bless({}, $type);
   $self->{buffer} = '';
   $self->{debug} = $params->{debug} || 0;
   $self->{cacrl} = $params->{cacrl} || undef;

	$self->{context} = Net::SSLeay::CTX_new();

   Net::SSLeay::CTX_use_RSAPrivateKey_file($self->{context}, $params->{key}, &Net::SSLeay::FILETYPE_PEM);
   Net::SSLeay::CTX_use_certificate_file($self->{context}, $params->{crt}, &Net::SSLeay::FILETYPE_PEM);
   if ($params->{cacrt}) {
      Net::SSLeay::CTX_load_verify_locations($self->{context}, $params->{cactr}, '');
      Net::SSLeay::CTX_set_client_CA_list($self->{context}, Net::SSLeay::load_client_CA_file($params->{cacrt}));
      Net::SSLeay::CTX_set_verify_depth($self->{context}, 5);
   }

   if ($params->{cipher}) {
      Net::SSLeay::CTX_set_cipher_list($self->{context}, "AES256-SHA");
   }

   $self->{bio} = Net::SSLeay::BIO_new(BIO_get_handler());
   $self->{ssl} = Net::SSLeay::new($self->{context});
   Net::SSLeay::set_bio($self->{ssl}, $self->{bio}, $self->{bio});

   if ($params->{clientcertrequest}) {
      my $orfilter = &Net::SSLeay::VERIFY_PEER
                   | &Net::SSLeay::VERIFY_CLIENT_ONCE;
      #$orfilter |=  &Net::SSLeay::VERIFY_FAIL_IF_NO_PEER_CERT;
      #   unless $params->{noblockbadclientcert};
      Net::SSLeay::set_verify($self->{ssl}, $orfilter, \&VERIFY);
   }
   
   $globalinfos = [0, 0, []];

   $self;
}

sub VERIFY {
   my ($ok, $x509_store_ctx) = @_;
   #print "VERIFY!\n";
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
   my @return = ();
   #print "GETONESTART: NETWORK -> SSL -> POE: ".hexdump(join("", @$data))."\n";
   #my $sent = 0;
   #print "Writing ".length(join("", @$data))." Bytes to BIO ".$self->{bio}."xxx".$self->{ssl}."\n";
   my $bio = $self->{bio};
   BIO_write($bio, join("", @$data));
   $self->doHandshake();
   [@return]
}

sub get_one {
   my $self = shift;
   #print "GETONE: BEGIN\n";
   my @return = ();
   $self->doHandshake();
   push(@return, '') if ($self->{buffer});
   my $data = Net::SSLeay::read($self->{ssl}, 65535);
   push(@return, $data) if $data;
   [@return]
}

sub get {
   #print "GET: BEGIN\n";
   die;
   my ($self, $chunks) = @_;
   my @return = ();
   #print "GET:\n";
   $self->doHandshake();
   push(@return, '') if ($self->{buffer});
   foreach my $data (@$chunks) {
      #print "GET: NETWORK -> SSL -> POE: ".join("", @$data)."\n";
      my $data = Net::SSLeay::read($self->{ssl}, 65535);
      #print "GET: Read ".length($data)." bytes.\n";
      push(@return, $data);
   }
   [@return]
}

sub put {
   my ($self, $chunks) = @_;
   #print "PUT: BEGIN\n";
   my @return = ();
   $self->doHandshake();
   foreach my $data (@$chunks) {
      #print "PUT: POE -> SSL -> NETWORK: ".$data."\r\n";
      if ($self->{accepted}) {
         if (defined($self->{sendbuf})) {
            foreach my $cdata (@{$self->{sendbuf}}) {
               die("PUT: Not all data given to SSL")
                  if (Net::SSLeay::write($self->{ssl}, $cdata) != length($data));
            }
            delete($self->{sendbuf});
         }
         die("PUT: Not all data given to SSL")
            if (Net::SSLeay::write($self->{ssl}, $data) != length($data));
         $self->doHandshake();
      } else {
         push(@{$self->{sendbuf}}, $data) if ($data);
      }
   }
   push(@return, $self->{buffer}) if $self->{buffer};
   $self->{buffer} = '';
   [@return]
}

sub get_pending {
  my $self = shift;
  #print "get_pending\n";
  #return [ $self->{buffer} ] if length $self->{buffer};
  return undef;
}

sub doHandshake {
   my $self = shift;
   unless ($self->{accepted}) {
      my $err = Net::SSLeay::accept($self->{ssl}) ;
      if ($err == 1) {
         $self->{infos} = [((@$globalinfos)[0..2])];
         $globalinfos = [0, 0, []];
         $self->{accepted}++;
      } else {
         my $err2 = Net::SSLeay::get_error($self->{ssl}, $err);
         die("ERROR: ".$err2) unless ($err2 == 5); # SSL_ERROR_SYSCALL
      }
   }
   my $bio = $self->{bio};
   my $data = BIO_read($bio);
   $self->{buffer} .= $data if ($data);
   return;
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
   return $self->{accepted} || 0;
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

Version 0.01

=head1 DESCRIPTION

This module allows to make a SSL TCP Server via a filter for POE::Wheel::ReadWrite.

The SSL Filter can be switched during runtime, for example if you want to first make plain text and then STARTTLS. You also can the POE::Filter::SSL with an other filter, for example POE::Filter::HTTPD (see advance example on this site), and have a HTTPS server.

Further features are
  - Full Nonblocking mode; no use of Sockets at all
  - client certificate verification
  - Send custom messages if client certificate is missing or invalid
  - CRL check.
  - Retrieve client certificate details (subect name, issuer name, certificate serial)

=head1 SYNOPSIS

   ...
      $heap->{listener} = POE::Wheel::SocketFactory->new(
         BindAddress  => '0.0.0.0',
         BindPort     => 443,
         SuccessEvent => 'socket_birth',
         ...
      },
   ...
   socket_birth => sub {
         my ($socket) = @_[ARG0];
         POE::Session->create(
            inline_states => {
               _start       => sub {
                  my ($heap, $kernel, $connected_socket) = @_[HEAP, KERNEL, ARG0];
                  $heap->{socket_wheel} = POE::Wheel::ReadWrite->new(
                     Handle     => $connected_socket,
                     Driver     => POE::Driver::SysRW->new(),
                     Filter     => POE::Filter::SSL->new({
                        crt    => 'server.crt',
                        key    => 'server.key',
                        debug  => 1
                     }),
                     InputEvent => 'socket_input',
                     ErrorEvent => 'socket_death',
                  );
               },
               socket_input => sub {
                  my ($kernel, $heap, $buf) = @_[KERNEL, HEAP, ARG0];
                  # This following line is needed to do the SSL handshake!
                  return $heap->{socket_wheel}->put() unless $buf;
                  my $content = "HTTP/1.0 OK\r\nContent-type: text/html\r\n\r\n";
                  $content .= "Welcome on the SSL encrypted TCP connection!<br>\r\n";
                  $content .= localtime(time());
                  $heap->{socket_wheel}->put($content);
                  $kernel->delay(_stop => 1);
               },
               _stop => sub {
                  delete $_[HEAP]->{socket_wheel} if ($_[HEAP]->{socket_wheel});
               }
            },
            args => [$socket],
         );
   ...

=head1 FUNCTIONS

=head2 new({option => "value", option2 => "value2", ...})

Returns a new POE::Filter::SSL object. It accepts as a hash the following options:

   debug
      Get debug messages during ssl handshake. Especially usefull
      for Server_SSLify_NonBlock_ClientCertVerifyAgainstCRL.

   crt
      The certificate for the server, normale file.crt.

   key
      The key of the certificate for the server, normale file.key.

   clientcertrequest
      The client gets requested for a client certificat during 
      ssl handshake

   cacrt
      The ca certificate, which is used to verificated the client
      certificates against a CA. Normaly a file like ca.crt.

=cut

sub blabla {
}

=head2 handshakeDone()

Returns true if the handshake is done and all data for hanshake has been written out.

=cut

sub handshakeDone {
   xxx ?
}

=head2 clientCertNotOnCRL(file)

Opens a CRL file, and verify if the serial of the client certificate
is not contained in the CRL file. No file caching is done, each call opens
the file again.

=cut

sub blabla {
}

=head2 clientCertIds()

Returns a array of every certificate found by OpenSSL. Each element
is again a array: First element is the value of X509_get_subject_name,
second is the value of X509_get_issuer_name and third element is the
serial of the certificate in binary form. You have to use split and use
"ord" to convert it to a readable form. Example:

   my ($certid) = ($heap->{sslfilter}->clientCertIds());
   $certid = $certid ? $certid->[0]."<br>".$certid->[1]."<br>SERIAL=".ord($certid->[2]) : 'No client certificate';

=cut

sub blabla {
}

=head2 clientCertValid()

Returns true if there is a client certificate that is valid. It
also tests against the crl, if you have set the "cacrl"
option on new().

=cut

sub blabla {
}

=head2 clientCertExists()

Returns true if there is a client certificate, that maybe
is untrusted.

=cut

sub blabla {
}

=head2 hexdump($string)

Returns string data in hex format.

For example:

  perl -e 'use POE::Component::SSLify::NonBlock; print POE::Component::SSLify::NonBlock::hexdump("test")."\n";'
  74:65:73:74

=head2 Private functions

=head3 BIO_get_handler()

=head3 BIO_read()

=head3 BIO_write()

=head3 VERIFY()

=head3 X509_get_serialNumber()

=head3 clone()

=head3 doHandshake()

=head3 get()

=head3 get_one()

=head3 get_one_start()

=head3 get_pending()

=head3 hello()

=head3 put()

=head3 verify_serial_against_crl_file()

Internal used to access OpenSSL.

=head1 ADVANCED EXAMPLE

   use strict;
   use warnings;
   use POE qw(Wheel::SocketFactory Wheel::ReadWrite Driver::SysRW Filter::SSL Filter::Stackable Filter::HTTPD);
   POE::Session->create(
      inline_states => {
         _start       => sub {
            my $heap = $_[HEAP];
            $heap->{listener} = POE::Wheel::SocketFactory->new(
               BindAddress  => '0.0.0.0',
               BindPort     => 443,
               Reuse        => 'yes',
               SuccessEvent => 'socket_birth',
               FailureEvent => 'socket_death',
            );
         },
         _stop => sub {
            my $heap = $_[HEAP];
            delete $heap->{listener};
            delete $heap->{session};
         },
         socket_birth => sub {
            my ($socket) = $_[ARG0];
            POE::Session->create(
               inline_states => {
                  _start       => sub {
                     my ($heap, $kernel, $connected_socket, $address, $port) = @_[HEAP, KERNEL, ARG0, ARG1, ARG2];
                     $heap->{sslfilter} = POE::Filter::SSL->new({
                        crt    => 'server.crt',
                        key    => 'server.key',
                        cactr  => 'ca.crt',
                        cipher => 'AES256-SHA',
                        cacrl  => 'ca.crl',
                        debug  => 1,
                        clientcertrequest => 1
                     });
                     $heap->{socket_wheel} = POE::Wheel::ReadWrite->new(
                        Handle     => $connected_socket,
                        Driver     => POE::Driver::SysRW->new(),
                        Filter     => $heap->{sslfilter},
                        InputEvent => 'socket_input',
                        ErrorEvent => 'socket_death',
                     );
                  },
                  socket_input => sub {
                     my ($kernel, $heap, $buf) = @_[KERNEL, HEAP, ARG0];
                     ### Uncomment if you want to use POE::Filter::HTTPD after the SSL handshake
                     #if ($heap->{sslfilter}->handshakeDone()) {
                     #   if (ref($heap->{socket_wheel}->get_input_filter()) ne "POE::Filter::Stackable") {
                     #      $heap->{socket_wheel}->set_input_filter(POE::Filter::Stackable->new(
                     #         Filters => [
                     #            $heap->{sslfilter},
                     #            POE::Filter::HTTPD->new()
                     #         ])
                     #      );
                     #   }
                     #}
                     # This following line is needed to do the SSL handshake!
                     return $heap->{socket_wheel}->put() unless $buf;
                     my ($certid) = ($heap->{sslfilter}->clientCertIds());
                     $certid = $certid ? $certid->[0]."<br>".$certid->[1]."<br>SERIAL=".ord($certid->[2]) : 'No client certificate';
                     my $content = "HTTP/1.0 OK\r\nContent-type: text/html\r\n\r\n";
                     if ($heap->{sslfilter}->clientCertValid()) {
                        $content .= "Hello <font color=green>valid</font> client Certifcate:";
                     } else {
                        $content .= "None or <font color=red>invalid</font> client certificate:";
                     }
                     $content .= "<hr>".$certid."<hr>";
                     $content .= "Your URL was: ".$buf->uri."<br>"
                        if (ref($buf) eq "HTTP::Request");
                     $content .= localtime(time());
                     $heap->{socket_wheel}->put($content);
                     $kernel->delay(_stop => 1);
                  },
                  _stop => sub {
                     delete $_[HEAP]->{socket_wheel} if ($_[HEAP]->{socket_wheel});
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

=head1 ACKNOWLEDGEMENTS

=head1 COPYRIGHT & LICENSE

Copyright 2010 Markus Mueller, all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut

1; # End of POE::Filter::SSL
