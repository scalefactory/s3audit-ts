import {Command, flags} from '@oclif/command'
import {S3} from 'aws-sdk'

import {S3Audit} from './@types'
import Bucket from './bucket'

const Listr = require('listr')

class S3Audit extends Command {
  static description = 'Audits S3 bucket settings'

  static args = []

  static flags = {
    bucket: flags.string({
      description: 'The name of a bucket to target'
    }),

    version: flags.version({char: 'v'}),
    help: flags.help({char: 'h'}),
  }

  private listrOptions = {
    exitOnError: false,
    collapse: false,
    concurrent: true
  }

  async run() {
    const {flags} = this.parse(S3Audit)
    const buckets: Bucket[] = []

    if (flags.bucket) {
      return this.auditBuckets([new Bucket(flags.bucket)]);
    }

    new S3().listBuckets((error: Object, data?: S3.Types.ListBucketsOutput) => {
      if (!data || data.Buckets === undefined) {
        return this.exit()
      }

      data.Buckets.forEach(bucket => {
        if (bucket.Name !== undefined) {
          buckets.push(new Bucket(bucket.Name))
        }
      })

      this.auditBuckets(buckets)
    })
  }

  private async auditBuckets(buckets: Array<Bucket>) {
    const tasks = new Listr([], this.listrOptions)

    buckets.forEach(bucket => {
      tasks.add([
        {
          title: bucket.name,
          task: async () => {
            return new Listr([
              {
                title: 'Bucket public access is blocked',
                task: () => this.checkBucketPublicAccess(bucket)
              },
              {
                title: 'Server side encryption is enabled',
                task: () => bucket.checkEncryptionIsEnabled()
              },
              {
                title: 'Bucket versioning is enabled',
                task: () => bucket.checkBucketVersioning()
              },
              {
                title: 'Bucket website is disabled',
                task: () => bucket.checkBucketWebsite()
              },
              {
                title: 'Bucket policy doesn\'t allow a wildcard entity',
                task: () => bucket.checkThatBucketPolicyDoesntAllowWildcardEntity()
              },
              {
                title: 'Bucket ACL doesn\'t allow access to "Everyone" or "Any authenticated AWS user"',
                task: () => bucket.checkBucketACL()
              },
              {
                title: 'Bucket logging is enabled',
                task: () => bucket.checkLoggingIsEnabled()
              }
            ], this.listrOptions)
          }
        }
      ])
    })

    tasks.run().catch((err: Error) => {})
  }

  private async checkBucketPublicAccess(bucket: Bucket) {
    const publicAccessBlockConfiguration: S3Audit.Types.PublicAccessBlockConfiguration =
      await bucket
        .checkPublicAccess()
        .catch(() => {
          throw new Error()
        })

    return new Listr([
      {
        title: 'BlockPublicAcls',
        task: () => {
          if (publicAccessBlockConfiguration.BlockPublicAcls !== true) {
            throw new Error()
          }
        }
      },
      {
        title: 'IgnorePublicAcls',
        task: () => {
          if (publicAccessBlockConfiguration.IgnorePublicAcls !== true) {
            throw new Error()
          }
        }
      },
      {
        title: 'BlockPublicPolicy',
        task: () => {
          if (publicAccessBlockConfiguration.BlockPublicPolicy !== true) {
            throw new Error()
          }
        }
      },
      {
        title: 'RestrictPublicBuckets',
        task: () => {
          if (publicAccessBlockConfiguration.RestrictPublicBuckets !== true) {
            throw new Error()
          }
        }
      }
    ], this.listrOptions)
  }
}

export = S3Audit
