import {S3} from 'aws-sdk'

export declare module S3Audit.Types {
  export interface Bucket {
    name: string
  }

  export interface CSVFields {
    [propName: string]: any;
    name?: string,
    BlockPublicAcls?: string | string | boolean,
    BlockPublicPolicy?: string | boolean,
    RestrictPublicBuckets?: string | boolean,
    IgnorePublicAcls?: string | boolean,
    sse?: string,
    versioning?: string | boolean,
    mfa_delete?: string | boolean,
    static_website?: string | boolean,
    bucket_policy?: string | boolean,
    bucket_acl?: string | boolean,
    logging?: string,
    cloudfront?: string
  }

  export interface Formatter {
    run(buckets: Array<Bucket>, includeChecks: Array<string>): void
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
