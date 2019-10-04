import {AWSError} from 'aws-sdk'

import {S3Audit} from '../@types'
import Bucket from '../bucket'

export default class Csv implements S3Audit.Types.Formatter {
  private output: any

  private fields: S3Audit.Types.CSVFields = {
    name: 'Bucket name',
    BlockPublicAcls: 'BlockPublicAcls is enabled',
    BlockPublicPolicy: 'BlockPublicPolicy is enabled',
    RestrictPublicBuckets: 'RestrictPublicBuckets is enabled',
    IgnorePublicAcls: 'IgnorePublicAcls is enabled',
    sse: 'Server side encryption algorith',
    versioning: 'Object versioning is enabled',
    mfa_delete: 'MFA Delete is enabled',
    static_website: 'Static website hosting is disabled',
    bucket_policy: 'Bucket policy doesn\'t allow a wildcard entity',
    bucket_acl: 'Bucket ACL doesn\'t allow public access',
    logging: 'Bucket logging target bucket'
  }

  constructor(output: any) {
    this.output = output
  }

  public async run(buckets: Array<Bucket>) {
    this.output(Object.values(this.fields).join(','))

    buckets.forEach(async bucket => {
      const bucketDetails: S3Audit.Types.CSVFields = {name: bucket.name}

      Promise.all([
        this.populatePublicAccessConfiguration(bucket, bucketDetails),
        this.populateSSEField(bucket, bucketDetails),
        this.populateLoggingField(bucket, bucketDetails),
        this.populateVersioningField(bucket, bucketDetails),
        this.populateStaticWebsiteField(bucket, bucketDetails),
        this.populatePolicyField(bucket, bucketDetails),
        this.populateACLField(bucket, bucketDetails),
        this.populateMFADeleteField(bucket, bucketDetails)
      ]).then(() => {
        const output: Array<string> = []

        Object.keys(this.fields).forEach((field: string) => {
          output.push(bucketDetails[field])
        })

        this.output(output.join(','))
      })
    })
  }

  private populatePublicAccessConfiguration(bucket: Bucket, bucketDetails: S3Audit.Types.CSVFields) {
    return new Promise(resolve => {
      bucket.getPublicAccessConfiguration()
        .then((bucketPublicAccessBlock: S3Audit.Types.PublicAccessBlockConfiguration) => {
          Object.assign(bucketDetails, bucketPublicAccessBlock)
        })
        .catch((error: AWSError) => {
          Object.assign(bucketDetails, {
            BlockPublicAcls: error.message,
            BlockPublicPolicy: error.message,
            RestrictPublicBuckets: error.message,
            IgnorePublicAcls: error.message
          })
        })
        .finally(() => resolve())
    })
  }

  private populateSSEField(bucket: Bucket, bucketDetails: S3Audit.Types.CSVFields) {
    return new Promise(resolve => {
      bucket.getSSEAlgorithm()
        .then((algorithm: string) => {
          bucketDetails.sse = algorithm || 'Disabled'
        })
        .catch((error: AWSError) => {
          bucketDetails.sse = error.message
        })
        .finally(() => resolve())
    })
  }

  private populateLoggingField(bucket: Bucket, bucketDetails: S3Audit.Types.CSVFields) {
    return new Promise(resolve => {
      bucket.getLoggingTargetBucket()
        .then((bucket: string) => {
          bucketDetails.logging = bucket || 'Disabled'
        })
        .catch((error: AWSError) => {
          bucketDetails.logging = error.message
        })
        .finally(() => resolve())
    })
  }

  private populateVersioningField(bucket: Bucket, bucketDetails: S3Audit.Types.CSVFields) {
    return new Promise(resolve => {
      bucket.hasVersioningEnabled()
        .then((isEnabled: boolean) => {
          bucketDetails.versioning = isEnabled
        })
        .catch((error: AWSError) => {
          bucketDetails.versioning = error.message
        })
        .finally(() => resolve())
    })
  }

  private populateStaticWebsiteField(bucket: Bucket, bucketDetails: S3Audit.Types.CSVFields) {
    return new Promise(resolve => {
      bucket.hasStaticWebsiteHosting()
        .then((isEnabled: boolean) => {
          bucketDetails.static_website = isEnabled
        })
        .catch((error: AWSError) => {
          bucketDetails.static_website = error.message
        })
        .finally(() => resolve())
    })
  }

  private populatePolicyField(bucket: Bucket, bucketDetails: S3Audit.Types.CSVFields) {
    return new Promise(resolve => {
      bucket.getPolicyWildcardEntities()
        .then((entities: Array<string>) => {
          bucketDetails.bucket_policy = entities.length > 0
        })
        .catch((error: AWSError) => {
          bucketDetails.bucket_policy = error.message
        })
        .finally(() => resolve())
    })
  }

  private populateACLField(bucket: Bucket, bucketDetails: S3Audit.Types.CSVFields) {
    return new Promise(resolve => {
      bucket.allowsPublicAccessViaACL()
        .then((isAllowed: boolean) => {
          bucketDetails.bucket_acl = isAllowed
        })
        .catch((error: AWSError) => {
          bucketDetails.bucket_acl = error.message
        })
        .finally(() => resolve())
    })
  }
  private populateMFADeleteField(bucket: Bucket, bucketDetails: S3Audit.Types.CSVFields) {
    return new Promise(resolve => {
      bucket.hasMFADeleteEnabled()
        .then((isEnabled: boolean) => {
          bucketDetails.mfa_delete = isEnabled
        })
        .catch((error: AWSError) => {
          bucketDetails.mfa_delete = error.message
        })
        .finally(() => resolve())
    })
  }
}
