# Perl interface for Amazon EC2 Systems Manager Parameter Store

# Description

Lightweight interface to Amazon's Parameter Store feature.  Use this
when:

- you want to store secrets
- you possibly want them encrypted
- you don't want to store them locally
- you sorta trust Amazon

# Usage

```
usage: ssm-parameter-store.pl options

Set/get/list parameters in AWS EC2 SSM Paramater Store

Options
-------
--list              list all parameters
--name=name         parameter name to set (multiple options allowed)
--value=value       parameter value to set
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
$ ssm-parameter-store.pl --list

Set 'foo' to 'bar':
$ ssm-parameter-store.pl --name=foo --value=bar

Set multiple parameters with encryption:
$ ssm-parameter-store.pl --name=foo --value=bar --description="foo description" 
--name=fiz --value=buz --key-id=alias/my-key

Get multiple parameters:
$ ssm-parameter-store.pl --name=foo --name=fiz --with-decryption

Get a single value (without decryption):
$ ssm-parameter-store.pl --name=foo --with-decryption

Hint: "jq" to parse the JSON:
$ ssm-parameter-store.pl --name=foo --with-decryption | jq -r .Parameters[].Value

Note[1]: Make sure your user credentials or EC2 role allows SSM access.
```

# Author

rlauer6@comcast.net
