package Net::Desk;

use 5.010;
use JSON;
use Mouse;
use Net::OAuth;
use LWP::UserAgent;
use URI;
use HTTP::Request::Common;
use Data::Random qw(rand_chars);
use Encode;

has 'debug' => (is => 'rw', isa => 'Bool', default => 0);
has 'error' => (is => 'rw', isa => 'Str', predicate => 'has_error');
has 'key' => (is => 'rw', isa => 'Str');
has 'secret' => (is => 'rw', isa => 'Str');
has 'login_link' => (is => 'rw', isa => 'Str');
has 'callback_url' => (is => 'rw', isa => 'Str', default => 'http://localhost:3000/callback');
has 'request_token' => (is => 'rw', isa => 'Str');
has 'request_secret' => (is => 'rw', isa => 'Str');
has 'access_token' => (is => 'rw', isa => 'Str');
has 'access_secret' => (is => 'rw', isa => 'Str');
has 'context' => (is => 'rw', isa => 'Str', default => 'sandbox');
has 'name' => (is => 'rw', isa => 'Str', default => 'yourcompany');

=head1 NAME

Net::Desk - The great new Net::Desk!

=head1 VERSION

Version 0.01

=cut

our $VERSION = '0.01';


=head1 SYNOPSIS

Quick summary of what the module does.

Perhaps a little code snippet.

    use Net::Desk;

    my $foo = Net::Desk->new();
    ...

=head1 EXPORT

A list of functions that can be exported.  You can delete this section
if you don't export anything, such as for a purely object-oriented module.

=head1 SUBROUTINES/METHODS

=cut

=head2 login

This sets up the initial OAuth handshake and returns the login URL. This
URL has to be clicked by the user and the user then has to accept
the application in desk. 

Desk then redirects back to the callback URL defined with
C<$self-E<gt>callback_url>. If the user already accepted the application the
redirect may happen without the user actually clicking anywhere.

=cut

sub login {
    my $self = shift;

    my $ua = LWP::UserAgent->new;

    my $request = Net::OAuth->request("request token")->new(
        consumer_key => $self->key,
        consumer_secret => $self->secret,
        request_url => 'https://'.$self->name.'.desk.com/v1/oauth/request_token',
        request_method => 'POST',
        signature_method => 'HMAC-SHA1',
        timestamp => time,
        nonce => $self->nonce,
        callback => $self->callback_url,
        callback_confirmed => ($self->callback_url ? 'true' : undef)
    );

    $request->sign;
    my $res = $ua->request(POST $request->to_url);

    if ($res->is_success) {
        my $response = Net::OAuth->response('request token')->from_post_body($res->content);
        $self->request_token($response->token);
        $self->request_secret($response->token_secret);
        print "Got Request Token ", $response->token, "\n" if $self->debug;
        print "Got Request Token Secret ", $response->token_secret, "\n" if $self->debug;
        return 'https://'.$self->name.'.desk.com/v1/oauth/authorize?oauth_token='.$response->token.'&oauth_callback='.$self->callback_url;
    }
    else {
        $self->error($res->status_line);
        warn "Something went wrong: " . $res->status_line;
    }
}

=head2 auth

The auth method changes the initial request token into access token that we need
for subsequent access to the API. This method only has to be called once
after login.

=cut

sub auth {
    my $self = shift;

    my $ua = LWP::UserAgent->new;
    my $request = Net::OAuth->request("access token")->new(
        consumer_key => $self->key,
        consumer_secret => $self->secret,
        request_url => 'https://'.$self->name.'.desk.com/v1/oauth/access_token',
        request_method => 'POST',
        signature_method => 'HMAC-SHA1',
        timestamp => time,
        nonce => $self->nonce,
        callback => $self->callback_url,
        token => $self->request_token,
        token_secret => $self->request_secret,
    );

    $request->sign;
    my $res = $ua->request(POST $request->to_url);

    if ($res->is_success) {
        my $response = Net::OAuth->response('access token')->from_post_body($res->content);
        $self->access_token($response->token);
        $self->access_secret($response->token_secret);
        print "Got Access Token ", $response->token, "\n" if $self->debug;
        print "Got Access Token Secret ", $response->token_secret, "\n" if $self->debug;
    }
    else {
        $self->error($res->status_line);
        warn "Something went wrong: ".$res->status_line;
    }
}

=head1 INTERNAL API

=head2 nonce

Generate a different nonce for every request.

=cut

sub nonce { join( '', rand_chars( size => 16, set => 'alphanumeric' )); }

=head2 _talk

_talk handles the access to the restricted resources. You should
normally not need to access this directly.

=cut


sub _talk {
    my $self    = shift;
    my $opts    = {};
    if(defined $_[0]  and ref($_[0]) eq "HASH") {
          # optional option hash present
        $opts = shift;
    }
    my $command = shift;
    my $method  = shift || 'GET';
    my $content = shift;
    my $extra_params = shift;

    if( !defined $opts->{error_handler} ) {
        $opts->{error_handler} = \&_talk_default_error_handler;
    }

    my $ua = LWP::UserAgent->new;

    my %opts = (
        consumer_key => $self->key,
        consumer_secret => $self->secret,
        request_url => 'https://'.$self->name.'.desk.com/v1/'.$command,
        request_method => $method,
        signature_method => 'HMAC-SHA1',
        timestamp => time,
        nonce => $self->nonce,
        #callback => $self->callback_url,
        token => $self->access_token,
        token_secret => $self->access_secret,
        extra_params => $extra_params
    );

    my $request = Net::OAuth->request("protected resource")->new( %opts );

    $request->sign;
    print "_talk URL: ", $request->to_url, "\n" if $self->debug;

    my $res;
    if($method =~ /get/i){
        $res = $ua->get($request->to_url);
    } else {
        $res = $ua->post($request->to_url, Content_Type => 'form-data', Content => $content );
    }

    if ($res->is_success) {
        print "Got Content ", $res->content, "\n" if $self->debug;
        my $data;
        eval {
            $data = from_json($res->content);
        };
        if($@) {
            # this doesn't look like JSON, might be file content
            return $res->content;
        }
        $data->{http_response_code} = $res->code();
        return to_json($data);
    } else {
        $self->error($res->status_line);
        return $opts->{error_handler}->($self, $res);
    }
    return;
}

sub _talk_default_error_handler {
    my $self    = shift;
    my $res     = shift;

    warn "Something went wrong: ".$res->status_line;
    return to_json({error => $res->status_line,
                    http_response_code => $res->code});
}

=head1 AUTHOR

Lenz Gschwendtner, C<< <norbu09 at cpan.org> >>

With Bug fixes from:

Greg Knauss C<< gknauss at eod.com >>

Chris Prather C<< chris at prather.org >>

Shinichiro Aska

[ktdreyer]

SureVoIP L<http://www.surevoip.co.uk>

=head1 BUGS

Please report any bugs through the web interface at
L<https://github.com/norbu09/Net-Desk/issues>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Net::Desk

You can also look for information at:

=over 4

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Net-Desk>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Net-Desk>

=item * Search CPAN

L<http://search.cpan.org/dist/Net-Desk/>

=back


=head1 COPYRIGHT & LICENSE

Copyright 2010 Lenz Gschwendtner.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.


=cut

=head1 AUTHOR

Lenz Gschwendtner, C<< <norbu09 at cpan.org> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-net-desk at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Net-Desk>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.




=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Net::Desk


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker (report bugs here)

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Net-Desk>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Net-Desk>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Net-Desk>

=item * Search CPAN

L<http://search.cpan.org/dist/Net-Desk/>

=back


=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

Copyright 2013 Lenz Gschwendtner.

This program is free software; you can redistribute it and/or modify it
under the terms of the the Artistic License (2.0). You may obtain a
copy of the full license at:

L<http://www.perlfoundation.org/artistic_license_2_0>

Any use, modification, and distribution of the Standard or Modified
Versions is governed by this Artistic License. By using, modifying or
distributing the Package, you accept this license. Do not use, modify,
or distribute the Package, if you do not accept this license.

If your Modified Version has been derived from a Modified Version made
by someone other than you, you are nevertheless required to ensure that
your Modified Version complies with the requirements of this license.

This license does not grant you the right to use any trademark, service
mark, tradename, or logo of the Copyright Holder.

This license includes the non-exclusive, worldwide, free-of-charge
patent license to make, have made, use, offer to sell, sell, import and
otherwise transfer the Package with respect to any patent claims
licensable by the Copyright Holder that are necessarily infringed by the
Package. If you institute patent litigation (including a cross-claim or
counterclaim) against any party alleging that the Package constitutes
direct or contributory patent infringement, then this Artistic License
to you shall terminate on the date that such litigation is filed.

Disclaimer of Warranty: THE PACKAGE IS PROVIDED BY THE COPYRIGHT HOLDER
AND CONTRIBUTORS "AS IS' AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES.
THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE, OR NON-INFRINGEMENT ARE DISCLAIMED TO THE EXTENT PERMITTED BY
YOUR LOCAL LAW. UNLESS REQUIRED BY LAW, NO COPYRIGHT HOLDER OR
CONTRIBUTOR WILL BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR
CONSEQUENTIAL DAMAGES ARISING IN ANY WAY OUT OF THE USE OF THE PACKAGE,
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


=cut

1; # End of Net::Desk
