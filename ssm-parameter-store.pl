#!/usr/bin/perl

use strict;
use warnings;

# Lightweight Perl interface to SSM Parameter Store
# ...minimum required to set/retrieve/delete parameters

package AWSCredentials;

use parent qw/Class::Accessor/;

__PACKAGE__->follow_best_practice;
__PACKAGE__->mk_accessors(qw/aws_secret_access_key aws_access_key_id token user_agent config profile debug/);

use HTTP::Request;
use LWP::UserAgent;
use Scalar::Util qw/reftype/;
use Data::Dumper;

sub new {
  my $class = shift;
  my $self = $class->SUPER::new(@_);

  unless ($self->get_user_agent) {
    $self->set_user_agent(new LWP::UserAgent);
  }

  unless ( $self->get_token || ($self->get_aws_secret_access_key && $self->get_aws_access_key_id) ) {
    $self->set_credentials();
  }

  $self;
}

sub set_credentials {
  my $self = shift;
    
  my $creds = $self->get_ec2_credentials($self->get_profile ? (profile => $self->get_profile) : ());
    
  if ( $creds->{aws_secret_access_key} && $creds->{aws_access_key_id} ) {
    $self->set_aws_secret_access_key($creds->{aws_secret_access_key});
    $self->set_aws_access_key_id($creds->{aws_access_key_id});
    $self->set_token($creds->{token});
  }
  else {
    die "no credentials available\n";
  }
}

=pod

=head2 get_ec2_credentials

get_ec2_credential( [options] );

=cut

sub get_ec2_credentials {
  my $self = shift;

  my %options = ref($_[0]) ? %{$_[0]} : @_;

  my $config = $options{config} || $self->get_config || {};

  $options{order} = $options{order} || [ qw/env config role file/ ];
    
  my $creds = {};
    
  foreach (@{$options{order}}) {
    /env/ && do {
      if ( $ENV{AWS_ACCESS_KEY_ID} && $ENV{AWS_SECRET_ACCESS_KEY} ) {
	@{$creds}{qw/source aws_access_key_id aws_secret_access_key/} = ('ENV',@ENV{qw/AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY/});
	last;
      }
    };

    /config/ && do {
      if ( ref($config) && reftype($config) eq 'HASH' ) {
	if ( exists $config->{AWS_ACCESS_KEY_ID} && $config->{AWS_ACCESS_KEY_ID} &&
	     exists $config->{AWS_SECRET_ACCESS_KEY} && $config->{AWS_SECRET_ACCESS_KEY} ) {
	  @{$creds}{qw/source aws_access_key_id aws_secret_access_key token/} =
	    ('default-config', @{$config}{qw/AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY/});
	  last;
	}
      }
    };
      
    /role/ && do {
      # try to get credentials from instance role
      my $url = 'http://169.254.169.254/latest/meta-data/iam/security-credentials/';
      
      my $ua = $self->get_user_agent;
      my $role;
	
      eval {
	# could be infinite, but I don't think so.  Either we get an
	# error ($@), or a non-200 response code
	while ( ! $creds->{token} ) {
	    
	  $url .= $role if $role;
	    
	  my $req = HTTP::Request->new( GET => $url );
	  my $rsp = $ua->request($req);

	  # if not 200, then get out of Dodge
	  last unless $rsp->is_success;
	    
	  if ( $role ) {
	    my $this = from_json($rsp->content);
	    @{$creds}{qw/source role aws_access_key_id aws_secret_access_key token expiration/} =
	      ('IAM',$role, @{$this}{qw/AccessKeyId SecretAccessKey Token Expiration/});
	  }
	  else {
	    $role = $rsp->content;

	    unless ($role) {
	      $creds = undef;
	      last;
	    }
	  }
	}
      };
	
      last if ! $@ && $creds->{role};
	
      $creds->{error} = $@ if $@;
    };
      
    /file/ && do {
      # look for ~/.aws/config
      use File::chdir;
      use File::HomeDir;

      foreach my $config ( ".aws/config", ".aws/credentials" ) { 
	local $CWD = home;
	next unless -e $config;
	  	  
	open my $fh, "<$config" or die "could not open credentials file!";

	# look for credentials...by interating through credentials file
	while (<$fh>) {
	  chomp;
	  # once we find a profile section that matches, undef it,
	  # but the existence of the hash member as undef will tell
	  # us to stop looking once we do match
	  if ( exists $options{profile} && defined $options{profile}) {
	    if (/^\s*\[\s*profile\s+$options{profile}\s*\]/) {
	      $options{profile} = undef;
	    }
	  }
	  elsif (exists $options{profile} && /^\s*\[\s*profile\s+/) {
	    last;
	  }
	  elsif (/^\s*aws_secret_access_key\s*=\s*(.*)$/) {
	    $creds->{aws_secret_access_key} = $1;
	    last if $creds->{aws_access_key_id};
	  }
	  elsif (/^\s*aws_access_key_id\s*=\s*(.*)$/) {
	    $creds->{aws_access_key_id} = $1;
	    last if $creds->{aws_secret_access_key};
	  }
	}
	  
	close $fh;
	  
	if ($self->get_debug) {
	  print STDERR Dumper [ $creds ];
	}

	$creds->{source} = $config if $creds->{aws_secret_access_key} && $creds->{aws_access_key_id};
      }
	
      last if $creds->{source};
    };
  }
    
  return $creds;
}

package AWSAPI;

use parent qw/Class::Accessor/;

use AWS::Signature4;
use HTTP::Request;
use LWP::UserAgent;
use Data::Dumper;
use JSON qw/to_json/;

__PACKAGE__->follow_best_practice;
__PACKAGE__->mk_accessors(qw/action api credentials region signer target url user_agent version debug/);


sub new {
  my $class = shift;
  my $self = $class->SUPER::new(@_);

  unless ($self->get_user_agent) {
    $self->set_user_agent(new LWP::UserAgent);
  }

  $self->set_signer(AWS::Signature4->new(-access_key => $self->get_credentials->get_aws_access_key_id,
					 -secret_key => $self->get_credentials->get_aws_secret_access_key,
					 $self->get_credentials->get_token ? (-security_token => $self->get_credentials->get_token) : ()
					)
		   );
    
  $self;
}

sub invoke_api {
  my $self = shift;
  my ($action, $options) = @_;

  $self->set_action($action);
    
  my $rsp = $self->submit(content => to_json($options || {}));
    
  if ( $self->get_debug ) {
    print STDERR Dumper [$rsp];
  }
    
  # probably want to decode content when there is an error, but this
  # will do for now
  unless ($rsp->is_success) {
    die $rsp->content;
  }
    
  return $rsp->content;
}

sub submit {
  my $self = shift;

  my %options = @_;

  $options{content_type} = $options{content_type} || 'application/x-amz-json-1.1';

  my $request = HTTP::Request->new('POST', $self->get_url);

  $request->content_type($options{content_type});
  $request->content($options{content});

  # some APIs want the version in the target, some don't. Sparse
  # documentation on X-Amz-Target. DDB & KMS seems to be able to use
  # this in lieu of query variables Action & Version, although there
  # is a lot of inconsisitency in the APIs.  DDB uses
  # DynamoDB_YYYYMMDD.Action while KMS will not take the version
  # that way and prefers TrentService.Action (with no version).
  # There is no explanation in any of the documentations as to what
  # "TrentService" might actually mean.
  if ( $self->get_version) {
    $self->set_target(sprintf("%s_%s.%s", $self->get_api, $self->get_version, $self->get_action));
  }
  else {
    $self->set_target(sprintf("%s.%s", $self->get_api, $self->get_action));
  }

  $request->header('X-Amz-Target', $self->get_target());

  # sign the request
  $self->get_signer->sign($request);

  # make the request, return response object
  if ( $self->get_debug ) {
    print STDERR Dumper([$request]);
  }

  $self->get_user_agent->request($request);
}

package SSM;

use vars qw/@ISA/;
@ISA = qw/AWSAPI/;

use JSON qw/from_json to_json/;
use Data::Dumper;

sub new {
  my $class = shift;
  my $options = shift || {};

  $options->{region} = $options->{region} || 'us-east-1';
  $options->{url} = $options->{url} || 'https://ssm.' . $options->{region} . '.amazonaws.com';

  $class->SUPER::new({ %$options, version  => undef, api => 'AmazonSSM' } );
}


sub describe_parameters {
  shift->invoke_api('DescribeParameters');
}

  
sub put_parameter {
  shift->invoke_api('PutParameter', shift);
}
 
sub get_parameter {
  return shift->invoke_api('GetParameter', shift);
}

sub delete_parameter {
  return shift->invoke_api('DeleteParameter', shift);
}

sub get_parameters {
  return shift->invoke_api('GetParameters', shift);
}


package main;

# +--------------------------+
# | MAIN PROGRAM STARTS HERE |
# +--------------------------+

use Getopt::Long;
use JSON qw/from_json/;

my %options;

GetOptions(\%options, 
	   "name=s@",	       # parameter name (may provide multiple)
	   "value=s@",	       # value for parameter
	   "delete=s",	       # delete parameter
	   "description=s@",   # parameter description
	   "profile=s",	       # config profile
	   "overwrite",	       # overwrite parameter values
	   "key-id=s",	       # KMS key arn
	   "list",	       # list all parameters
	   "with-decryption",  # when fetching
	   "debug",	       # output request/response to STDERR
	   "help"
	  );

if (exists $options{help} ) {
  print <<eom;
usage: ssm-parameter-store.pl options

Set/get/list parameters in AWS EC2 SSM Paramater Store

Options
-------
--list              list all parameters
--name=name         parameter name to set (multiple options allowed)
--value=value       parameter value to set
--delete=name       delete a parameter
--description=text  description of parameter
--with-decryption   decrypt values on output
--debug             print request/response, etc
--overwrite         overwrite values
--key-id            KMS arn for encryption
--profile           credential profile ~/.aws/config
--help              this

Examples
--------

List all parameters:
\$ ssm-parameter-store.pl --list

Set 'foo' to 'bar':
\$ ssm-parameter-store.pl --name=foo --value=bar

Set multiple parameters with encryption:
\$ ssm-parameter-store.pl --name=foo --value=bar --description="foo description" \\
--name=fiz --value=buz --key-id=alias/my-key

Get multiple parameters:
\$ ssm-parameter-store.pl --name=foo --name=fiz --with-decryption

Get a single value (without decryption):
\$ ssm-parameter-store.pl --name=foo --with-decryption

Hint: "jq" to parse the JSON:
\$ ssm-parameter-store.pl --name=foo --with-decryption | jq -r .Parameters[].Value

Note[1]: Make sure your user credentials or EC2 role allows SSM access.
eom

  exit;
}

my $ssm = SSM->new({
		    version => '20141106', # doesn't seem to be required for this API
		    credentials => AWSCredentials->new({profile => $options{profile}}),
		    debug => $options{debug} # change to 1 to see request/response
		   }
		  );

if ( exists $options{list} ) {
  print $ssm->describe_parameters(); # {MaxResults => 1000});
}
elsif ( exists $options{delete} ) {
  $ssm->delete_parameter({ Name => $options{delete}});
}
else {
  if ( exists $options{name} ) {
    $options{name} = ref($options{name}) ? $options{name} : [ $options{name} ];
  }
  
  if ( exists $options{value} ) {
    $options{value} = ref($options{value}) ? $options{value} : [ $options{value} ];

    if ( exists $options{description} && @{$options{value}} != @{$options{description}} ) {
      die "error: not enough --description options\n";
    }

    $options{description} = ref($options{description}) ? $options{description} : [ $options{description} ];
  }

  my $names = $options{name};
  my $descriptions = $options{description};

  if ( exists $options{value} ) {

    foreach (0..$#$names) {
      if ($options{debug} ) {
	print STDERR sprintf("%s[$_]->%s[$_]\n", $names->[$_], $options{value}->[$_]);
      }
    
      $ssm->put_parameter({
			   Name        => $names->[$_],
			   Overwrite   => exists $options{overwrite} ? JSON::true : JSON::false,
			   $descriptions ? (Description => $descriptions->[$_]) : (),
			   Value       => $options{value}->[$_],
			   Type        => $options{'key-id'} ? 'SecureString' : 'String',
			   $options{'key-id'} ? (KeyId => $options{'key-id'}) : ()
			  });
    }
  }
  else {
    print $ssm->get_parameters({
				Names => $names,
				WithDecryption => $options{'with-decryption'} ? JSON::true : JSON::false
			       }
			      );
  }
}

exit;
