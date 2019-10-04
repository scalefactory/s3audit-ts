import {Command, flags} from '@oclif/command'
import {AWSError, S3} from 'aws-sdk'

import {S3Audit} from './@types'
import Bucket from './bucket'

import {default as ConsoleFormatter} from './formatters/console'

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

  async run() {
    const {flags} = this.parse(S3Audit)
    const buckets: Bucket[] = []

    if (flags.bucket) {
      return this.auditBuckets([new Bucket(flags.bucket)])
    }

    new S3().listBuckets((error: AWSError, data?: S3.Types.ListBucketsOutput) => {
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
    new ConsoleFormatter().run(buckets)
  }
}

export = S3Audit
