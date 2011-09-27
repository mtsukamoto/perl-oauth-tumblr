package OAuth::Tumblr;

use warnings;
use strict;
use Carp;
use version; our $VERSION = qv('0.0.1');

use base qw(
	Class::ErrorHandler
	Class::Accessor::Fast
);

__PACKAGE__->mk_accessors(qw(
	consumer_key
	consumer_secret
	callback_url
	dir
	debug
	access_token
));

use OAuth::Lite::Consumer;
use OAuth::Lite::AuthMethod qw(:all);
use CGI;
use CGI::Session;
use File::Slurp;

sub new {
	my ($class, %args) = @_;
	$args{'dir'} ||= '.';
	$args{'dir'} =~ s/(.)\/+$/$1/;
	my $self = bless { %args }, $class;
	$self;
}

sub query {
	my $self = shift;
	$self->{'query'} = shift if (@_);
	$self->{'query'} ||= CGI->new;
	return $self->{'query'};
}

sub session {
	my $self = shift;
	$self->{'session'} = shift if (@_);
	unless ($self->{'session'}) {
		$self->{$_} || return $self->error("$_ is required.") for (qw(dir));
		foreach my $dir ($self->dir(), $self->dir() . '/session') {
			next if (-d $dir);
			mkdir($dir, 0777) || return $self->error("Can't make directory '$dir'.");
		}
		$self->{'session'} = CGI::Session->new(undef, $self->query, {Directory => $self->dir() . '/session'});
	}
	return $self->{'session'};
}

sub consumer {
	my $self = shift;
	$self->{'consumer'} = shift if (@_);
	unless ($self->{'consumer'}) {
		$self->{$_} || return $self->error("$_ is required.") for (qw(consumer_key consumer_secret callback_url));
		$self->{'consumer'} ||= OAuth::Lite::Consumer->new(
			consumer_key	=> $self->consumer_key,
			consumer_secret => $self->consumer_secret,
			site => "http://www.tumblr.com/",
			request_token_path => "http://www.tumblr.com/oauth/request_token",
			access_token_path => "http://www.tumblr.com/oauth/access_token",
			authorize_path => "http://www.tumblr.com/oauth/authorize",
			callback_url => $self->callback_url,
		);
	}
	return $self->{'consumer'};
}

sub oauth {
	my $self = shift;
	
	my $consumer = $self->consumer || return;
	my $query    = $self->query    || return;
	my $session  = $self->session  || return;

	if (not ($query->param('oauth_token') && $query->param('oauth_verifier'))) {
		# get request token
		$consumer->{'auth_method'} = POST_BODY;
		$self->log(sprintf("get_request_token(consumer_key:%s, consumer_secret: %s)", $consumer->consumer_key, $consumer->consumer_secret));
		my $request_token = $consumer->get_request_token();
		unless ($request_token) {
			$self->log(sprintf('get_request_token failed (%s)', $consumer->errstr));
			return $self->error(sprintf('get_request_token failed (%s)', $consumer->errstr));
		}
		$self->log(sprintf('get_request_token succeeded (%s)', $request_token->as_encoded));

		# get authorization page url and redirect
		my $uri = $consumer->url_to_authorize( token => $request_token );
		$session->param( request_token => $request_token );
		my $cookie = $query->cookie(-name=>$CGI::Session::NAME, -value=>$session->id);
		$self->log(sprintf('redirect to %s', $uri));
		print $query->redirect(-uri=>$uri,-cookie=>$cookie);
		exit;
	} else {
		# get access_token
		$self->log(sprintf("get_access_token(verifier:%s, consumer_secret: %s)", $query->param('oauth_verifier'), $session->param('request_token')->as_encoded));
		my $access_token = eval {
			$consumer->get_access_token(
				token    => $session->param('request_token'),
				verifier => $query->param('oauth_verifier'),
			);
		};
		return $self->error('get_access_token failed (' . $@ . ')') if ($@);
		return $self->error('get_access_token failed (' . $consumer->errstr . ')') if (not $access_token);
		
		$self->log(sprintf('get_access_token succeeded (%s)', $access_token->as_encoded));
		$self->access_token($access_token);
		return $access_token;
	}
}

sub store_token {
	my ($self, $key, $token) = @_;
	$token ||= $self->access_token;
	return $self->error('Access token is not exist.') unless $token;
	foreach my $dir ($self->dir(), $self->dir() . '/token') {
		next if (-d $dir);
		mkdir($dir, 0777) || return $self->error("Can't make directory '$dir'.");
	}
	my $encoded = $token->as_encoded;
	my $file = $self->dir() . '/token/' . $key;
	File::Slurp::write_file($file, $encoded) || return $self->error("Can't write file '$file'.");
	return 1;
}

sub load_token {
	my ($self, $key) = @_;
	my $file = $self->dir() . '/token/' . $key;
	return $self->error("'$file' is not exists.") unless (-f $file);
	my $encoded = File::Slurp::read_file($file) || return $self->error("Can't read file '$file'.");
	my $token = OAuth::Lite::Token->from_encoded($encoded);
	return $token;
}

sub log {
	my $self = shift;
	return if (not $self->debug);
	my @lines = @_;
	chomp(@lines);
	foreach my $dir ($self->dir(), $self->dir() . '/log') {
		next if (-d $dir);
		mkdir($dir, 0777) || return $self->error("Can't make directory '$dir'.");
	}
	my $file = sprintf('%s/log/%s.txt', $self->dir(), $self->session->id);
	File::Slurp::write_file($file, {append => 1}, join("\n", @lines, ''));
}

# Module implementation here


1; # Magic true value required at end of module
__END__

=head1 NAME

OAuth::Tumblr - OAuth for tumblr with OAuth::Lite::Consumer


=head1 VERSION

This document describes OAuth::Tumblr version 0.0.1

=head1 SYNOPSIS

    use OAuth::Tumblr;

    my $oauth = OAuth::Tumblr->new(
        'consumer_key'    => 'YOUR_CONSUMER_KEY',
        'consumer_secret' => 'YOUR_CONSUMER_SECRET',
        'callback_url'    => 'YOUR_CGI_URL',
        'dir'             => './data',
    );

    my $token = $oauth->oauth || die $oauth->errstr unless ($token);

    my $req = $oauth->consumer->gen_oauth_request(
        method => 'POST',
        url => 'http://api.tumblr.com/v2/user/info',
        token => $token,
    );

=head1 DESCRIPTION

This module makes OAuth for Tumbla API easy.

=head1 INTERFACE 

=head2 new

Constructor. Acceptable argments are below.

=over 4

=item consumer_key

Consumer key. Required to execute oauth method.

=item consumer_secret

Consumer secret. Required to execute oauth method.

=item callback_url

Callback url (means your cgi url). Required to execute oauth method.

=item query

CGI moduke instance. Optional, it generated automatically when omitted.

=item session

CGI::Session moduke instance. Optional, it generated automatically when omitted.

=item dir

Data directory. Required to omit ssession, to execute load_token or store_token.

=back

=head2 consumer_key

Accessor for consumer_key.

=head2 consumer_secret

Accessor for consumer_secret.

=head2 callback_url

Accessor for callback_url.

=head2 dir

Accessor for dir.

=head2 access_token

Accessor for latest access_token.

=head2 query

Accessor for CGI instance.
When query has omitted on construction, it generates CGI instance.

=head2 session

Accessor for CGI:Session instance.
When session has omitted on construction, it generates CGI::Session instance and requires dir.

=head2 consumer

Accessor for OAuth::Lite::Consumer instance.
It generates OAuth::Lite::Consumer instance on first time and requires consumer_key, consumer_secret and callback_url.

=head2 oauth

On first access (without oauth_token and oauth_verifier), this method gets request token and redirects to authorization page.

On second access (returned from authorizaion page with oauth_token and oauth_verifier), this method gets and returns access token.

=head2 store_token

Store token with specified key (first argument).

=head2 load_token

Load token for specified key (first argument).

=head2 debug

Accessor for debug.

=head2 log

Internal method. Output log into file when debug is true.

=head1 DIAGNOSTICS

=over

=item C<< %S is required. >>

You haven't specified %s by constructor argument or accessor.

=item C<< Can't make directory '%S'. >>

OAuth::Tumblr failed to access (or make) directory.

=item C<< Can't write file '%S'. >>

OAuth::Tumblr failed to write file.

=item C<< Can't read file '%S'. >>

OAuth::Tumblr failed to read file.

=item C<< '%S' is not exists. >>

OAuth::Tumblr failed to find file.

=item C<< get_request_token failed (%S) >>

OAuth::Lite::Consumer->get_request_token filed.

=item C<< get_access_token failed (%S) >>

OAuth::Lite::Consumer->get_access_token filed.

=item C<< Access token is not exist. >>

You haven't specified or oauthed before store_token.

=back

=head1 CONFIGURATION AND ENVIRONMENT

OAuth::Tumblr requires no configuration files or environment variables.

=head1 DEPENDENCIES

=over 4

=item * Class::ErrorHandler

=item * Class::Accessor::Fast

=item * OAuth::Lite

=item * CGI

=item * CGI::Session

=item * File::Slurp

=back

=head1 SEE ALSO 

http://www.tumblr.com/oauth/apps

http://www.tumblr.com/docs/en/api/v2

https://sites.google.com/site/tsukamoto/doc/tumblr/api-v2-20110807-1911

OAuth::Lite::Consumer

=head1 AUTHOR

Makio Tsukamoto  C<< <tsukamoto@gmail.com> >>


=head1 LICENCE AND COPYRIGHT

Copyright (c) 2011, Makio Tsukamoto C<< <tsukamoto@gmail.com> >>. All rights reserved.

This module is free software; you can redistribute it and/or
modify it under the same terms as Perl itself. See L<perlartistic>.


=head1 DISCLAIMER OF WARRANTY

BECAUSE THIS SOFTWARE IS LICENSED FREE OF CHARGE, THERE IS NO WARRANTY
FOR THE SOFTWARE, TO THE EXTENT PERMITTED BY APPLICABLE LAW. EXCEPT WHEN
OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES
PROVIDE THE SOFTWARE "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER
EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE
ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE SOFTWARE IS WITH
YOU. SHOULD THE SOFTWARE PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL
NECESSARY SERVICING, REPAIR, OR CORRECTION.

IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING
WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY MODIFY AND/OR
REDISTRIBUTE THE SOFTWARE AS PERMITTED BY THE ABOVE LICENCE, BE
LIABLE TO YOU FOR DAMAGES, INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL,
OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OR INABILITY TO USE
THE SOFTWARE (INCLUDING BUT NOT LIMITED TO LOSS OF DATA OR DATA BEING
RENDERED INACCURATE OR LOSSES SUSTAINED BY YOU OR THIRD PARTIES OR A
FAILURE OF THE SOFTWARE TO OPERATE WITH ANY OTHER SOFTWARE), EVEN IF
SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE POSSIBILITY OF
SUCH DAMAGES.
