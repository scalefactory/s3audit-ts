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
      return this.auditBuckets([new Bucket(flags.bucket)])
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

  private auditBuckets(buckets: Array<Bucket>) {
    const tasks = new Listr([], this.listrOptions)

    buckets.forEach(bucket => {
      tasks.add([
        {
          title: bucket.name,
          task: () => {
            return new Listr([
              {
                title: 'Bucket public access configuration',
                task: () =>
                  new Listr([
                    {
                      title: 'BlockPublicAcls',
                      task: (context: any, task: S3Audit.Types.ListrTask) => this.checkPublicAccesBlockFor(task, bucket, 'BlockPublicAcls')
                    },
                    {
                      title: 'IgnorePublicAcls',
                      task: (context: any, task: S3Audit.Types.ListrTask) => this.checkPublicAccesBlockFor(task, bucket, 'IgnorePublicAcls')
                    },
                    {
                      title: 'BlockPublicPolicy',
                      task: (context: any, task: S3Audit.Types.ListrTask) => this.checkPublicAccesBlockFor(task, bucket, 'BlockPublicPolicy')
                    },
                    {
                      title: 'RestrictPublicBuckets',
                      task: (context: any, task: S3Audit.Types.ListrTask) => this.checkPublicAccesBlockFor(task, bucket, 'RestrictPublicBuckets')
                    }
                  ], this.listrOptions)

              },
              {
                title: 'Server side encryption is enabled',
                task: (context: any, task: S3Audit.Types.ListrTask) => this.checkBucketEncryption(task, bucket)
              },
              {
                title: 'Object versioning is enabled',
                task: (context: any, task: S3Audit.Types.ListrTask) => this.checkBucketVersioning(task, bucket)
              },
              {
                title: 'Static website hosting is disabled',
                task: (context: any, task: S3Audit.Types.ListrTask) => this.checkBucketWebsite(task, bucket)
              },
              {
                title: 'Bucket policy doesn\'t allow a wildcard entity',
                task: (context: any, task: S3Audit.Types.ListrTask) => this.checkThatBucketPolicyDoesntAllowWildcardEntity(task, bucket)
              },
              {
                title: 'Bucket ACL doesn\'t allow access to "Everyone" or "Any authenticated AWS user"',
                task: (context: any, task: S3Audit.Types.ListrTask) => this.checkBucketAcl(task, bucket)
              },
              {
                title: 'Logging is enabled',
                task: (context: any, task: S3Audit.Types.ListrTask) => this.checkBucketLogging(task, bucket)
              }
            ], this.listrOptions)
          }
        }
      ])
    })

    new Listr([
      {
        title: `Checking ${buckets.length} bucket${buckets.length === 1 ? '' : 's'}`,
        task: () => tasks
      }
    ]).run().catch((err: Error) => {})
  }

  private async checkPublicAccesBlockFor(task: S3Audit.Types.ListrTask, bucket: Bucket, setting: string) {
    const publicAccessBlockConfiguration: S3Audit.Types.PublicAccessBlockConfiguration = await bucket.getPublicAccessConfiguration()

    if (publicAccessBlockConfiguration[setting] === false) {
      task.title = `${setting} is set to false`

      throw new Error()
    }
  }

  private async checkBucketEncryption(task: S3Audit.Types.ListrTask, bucket: Bucket) {
    const algorithm = await bucket.hasEncryptionEnabled()

    if (!algorithm) {
      task.title = 'Server side encryption is not enabled'

      throw new Error()
    }

    task.message = `Encryption algorithm is ${algorithm}`
  }

  private async checkBucketLogging(task: S3Audit.Types.ListrTask, bucket: Bucket) {
    const targetBucket = await bucket.hasLoggingEnabled()

    if (targetBucket === null) {
      task.title = 'Logging is not enabled'

      throw new Error()
    }

    task.message = `Logging to ${targetBucket}`
  }

  private async checkBucketVersioning(task: S3Audit.Types.ListrTask, bucket: Bucket) {
    const isEnabled = await bucket.hasVersioningEnabled()

    if (isEnabled === false) {
      task.title = 'Object versioning is not enabled'

      throw new Error()
    }
  }

  private async checkBucketWebsite(task: S3Audit.Types.ListrTask, bucket: Bucket) {
    const isEnabled = await bucket.hasStaticWebsiteHosting()

    if (isEnabled === true) {
      task.title = 'Static website hosting is enabled'

      throw new Error()
    }
  }

  private async checkThatBucketPolicyDoesntAllowWildcardEntity(task: S3Audit.Types.ListrTask, bucket: Bucket) {
    const statements = await bucket.getPolicyWildcardEntities()

    if (statements.length > 0) {
      task.message = `Bucket has ${statements.length} statement${statements.length === 1 ? '' : 's'} with wildcard entities`

      throw new Error()
    }
  }

  private async checkBucketAcl(task: S3Audit.Types.ListrTask, bucket: Bucket) {
    const allowsPublicAccess = await bucket.allowsPublicAccessViaACL()

    if (allowsPublicAccess === true) {
      task.title = 'Bucket allows public access via ACL'

      throw new Error()
    }
  }
}

export = S3Audit
