s3audit
==================

Checks the settings for all S3 buckets in an AWS account for public access

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

  ❯ s3audit-demo
    ❯ Bucket public access is blocked
      ✖ BlockPublicAcls
      ✖ IgnorePublicAcls
      ✖ BlockPublicPolicy
      ✖ RestrictPublicBuckets
    ✖ Server side encryption is enabled
    ✖ Bucket versioning is enabled
    ✔ Bucket website is disabled
    ✔ Bucket policy doesn't allow a wildcard entity
    ✔ Bucket ACL doesn't allow access to "Everyone" or "Any authenticated AWS user"
```

<!-- usagestop -->
