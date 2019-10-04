import {S3Audit} from '../@types'
import Bucket from '../bucket'
import { bool } from 'aws-sdk/clients/signer'

export default class Csv implements S3Audit.Types.Formatter {
  private output: any

  private fields = {
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
      const bucketDetails: any = {name: bucket.name}

      Promise.all([
        bucket.getPublicAccessConfiguration().then((bucketPublicAccessBlock: S3Audit.Types.PublicAccessBlockConfiguration) => {
          Object.assign(bucketDetails, bucketPublicAccessBlock)
        }),

        bucket.getSSEAlgorithm().then((algorithm: string) => {
          bucketDetails.sse = algorithm || 'None'
        }),

        bucket.getLoggingTargetBucket().then((bucket: string) => {
          bucketDetails.logging = bucket || 'Disabled'
        }),

        bucket.hasVersioningEnabled().then((isEnabled: bool) => {
          bucketDetails.versioning = isEnabled
        }),

        bucket.hasStaticWebsiteHosting().then((isEnabled: bool) => {
          bucketDetails.static_website = isEnabled
        }),

        bucket.getPolicyWildcardEntities().then((entities: Array<string>) => {
          bucketDetails.bucket_policy = entities.length > 0
        }),

        bucket.allowsPublicAccessViaACL().then((isAllowed: bool) => {
          bucketDetails.bucket_acl = isAllowed
        }),

        bucket.hasMFADeleteEnabled().then((isEnabled: bool) => {
          bucketDetails.mfa_delete = isEnabled
        })
      ]).then(() => {
        const output: Array<string> = []

        Object.keys(this.fields).forEach((field: string) => {
          output.push(bucketDetails[field])
        })

        this.output(output.join(','))
      })
    })
  }
}
