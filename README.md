s3audit
==================

Checks the settings for all S3 buckets in an AWS account for public access

![GitHub package.json version](https://img.shields.io/github/package-json/v/ScaleFactory/s3audit.svg)
[![oclif](https://img.shields.io/badge/cli-oclif-brightgreen.svg)](https://oclif.io)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

<!-- toc -->
* [Usage](#usage)
<!-- tocstop -->

# Usage
<!-- usage -->

### Node
AWS credentials will be taken from environment variables.
It is recommended to run this in combination with [AWS Vault](https://github.com/99designs/aws-vault)

```sh-session
$ npm install
$ aws-vault exec <profile> -- ./bin/run
```

<!-- usagestop -->
