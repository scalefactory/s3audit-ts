import {S3} from 'aws-sdk'

export declare module S3Audit.Types {
  export interface Bucket {
    name: string
  }

  export interface Formatter {
    run(buckets: Array<Bucket>): void
  }

  export interface PublicAccessBlockConfiguration {
    [propName: string]: any;
    BlockPublicAcls?: boolean
    BlockPublicPolicy?: boolean
    RestrictPublicBuckets?: boolean
    IgnorePublicAcls?: boolean
  }

  export interface S3RequestProperties {
    Bucket: S3.Types.BucketName
  }

  export interface ListrTask {
    title: string
    output: string
    skip(reason: string): void
  }
}
