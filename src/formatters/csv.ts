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
    logging: 'Bucket logging target bucket',
    cloudfront: 'CloudFront Origin Access Identities'
  }

  private fieldsToChecks: any = {
    BlockPublicAcls: 'public-access-config',
    BlockPublicPolicy: 'public-access-config',
    RestrictPublicBuckets: 'public-access-config',
    IgnorePublicAcls: 'public-access-config',
    sse: 'sse',
    versioning: 'versioning',
    mfa_delete: 'mfa-delete',
    static_website: 'websited',
    bucket_policy: 'policy',
    bucket_acl: 'acl',
    logging: 'logging',
    cloudfront: 'cloudfront'
  }

  constructor(output: any) {
    this.output = output
  }

  public async run(buckets: Array<Bucket>, checks: Array<string>) {
    const includeFields: Array<string> = this.getIncludedFields(checks)
    const headings = includeFields.map((field: string) => this.fields[field])

    this.output(headings.join(','))

    buckets.forEach(async bucket => {
      const bucketDetails: S3Audit.Types.CSVFields = {name: bucket.name}

      Promise.all(this.getEnabledCheckPromises(checks, bucket, bucketDetails)).then(() => {
        const output: Array<string> = []

        includeFields.forEach((field: string) => {
          output.push(bucketDetails[field])
        })

        this.output(output.join(','))
      })
    })
  }

  private getEnabledCheckPromises(checks: Array<string>, bucket: Bucket, bucketDetails: S3Audit.Types.CSVFields): Array<Promise<any>> {
    const promises: Array<Promise<any>> = []

    if (checks.includes('public-access-config')) {
      promises.push(this.populatePublicAccessConfiguration(bucket, bucketDetails))
    }

    if (checks.includes('sse')) {
      promises.push(this.populateSSEField(bucket, bucketDetails))
    }

    if (checks.includes('logging')) {
      promises.push(this.populateLoggingField(bucket, bucketDetails))
    }

    if (checks.includes('versioning')) {
      promises.push(this.populateVersioningField(bucket, bucketDetails))
    }

    if (checks.includes('website')) {
      promises.push(this.populateStaticWebsiteField(bucket, bucketDetails))
    }

    if (checks.includes('policy')) {
      promises.push(this.populatePolicyField(bucket, bucketDetails))
    }

    if (checks.includes('acl')) {
      promises.push(this.populateACLField(bucket, bucketDetails))
    }

    if (checks.includes('mfa-delete')) {
      promises.push(this.populateMFADeleteField(bucket, bucketDetails))
    }

    if (checks.includes('cloudfront')) {
      promises.push(this.populateCloudfrontField(bucket, bucketDetails))
    }

    return promises
  }

  private getIncludedFields(checks: Array<string>): Array<string> {
    return Object.keys(this.fields).filter((field: string) => {
      if (this.fieldsToChecks[field] === undefined) {
        return true
      }

      return checks.includes(this.fieldsToChecks[field])
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
          bucketDetails.bucket_policy = entities.length === 0
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
        .then((isPublic: boolean) => {
          bucketDetails.bucket_acl = isPublic === false
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

  private populateCloudfrontField(bucket: Bucket, bucketDetails: S3Audit.Types.CSVFields) {
    return new Promise(resolve => {
      bucket.getCloudFrontOriginAccessIdentities()
        .then((identities: Array<string>) => {
          bucketDetails.cloudfront = identities.length === 0 ?
            'None'
            : identities.join(', ')
        })
        .catch((error: AWSError) => {
          bucketDetails.cloudfront = error.message
        })
        .finally(() => resolve())
    })
  }
}
