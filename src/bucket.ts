import {AWSError, S3} from 'aws-sdk'

import {S3Audit} from './@types'

export default class Bucket {
  public name: string

  private bucketVersioning?: S3.Types.GetBucketVersioningOutput
  private publicAccessConfiguration?: S3Audit.Types.PublicAccessBlockConfiguration
  private requestProperties: S3Audit.Types.S3RequestProperties
  private s3: S3

  constructor(name: string) {
    this.name = name
    this.requestProperties = {Bucket: this.name}
    this.s3 = new S3()
  }

  public async allowsPublicAccessViaACL(): Promise<any> {
    return new Promise((resolve, reject) => {
      this.s3.getBucketAcl(this.requestProperties, (error: AWSError, data: S3.Types.GetBucketAclOutput) => {
        if (error !== null) {
          return reject(error)
        }

        if (data === null || ! Array.isArray(data.Grants) || data.Grants.length === 0) {
          return resolve(false)
        }

        for (let grant of data.Grants) {
          if (grant.Grantee === undefined || grant.Grantee.Type !== 'Group' || grant.Grantee.URI === undefined) {
            continue
          }

          // tslint:disable-next-line:no-http-string
          if (['http://acs.amazonaws.com/groups/global/AllUsers', 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'].includes(grant.Grantee.URI)) {
            return resolve(true)
          }
        }

        resolve(false)
      })
    })
  }

  public async getCloudFrontOriginAccessIdentities(): Promise<any> {
    const cloudfrontPrefix = 'arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity '

    return new Promise((resolve, reject) => {
      this.s3.getBucketPolicy(this.requestProperties, (error: AWSError, data: S3.Types.GetBucketPolicyOutput) => {
        if (error !== null && error.code !== 'NoSuchBucketPolicy') {
          return reject(error)
        }

        if (data === null || data.Policy === undefined) {
          return resolve([])
        }

        const policy = JSON.parse(data.Policy)
        const identities: Array<string> = []

        for (let statement of policy.Statement) {
          if (statement.Principal === undefined || statement.Principal.AWS === undefined) {
            continue
          }

          const principals = Array.isArray(statement.Principal.AWS) ?
            statement.Principal.AWS
            : [statement.Principal.AWS]

          for (let principal of principals) {
            if (principal.indexOf(cloudfrontPrefix) === 0) {
              const identity = principal.replace(cloudfrontPrefix, '')

              identities.push(identity)
            }
          }
        }

        resolve(identities)
      })
    })
  }

  public async getPublicAccessConfiguration(): Promise<any> {
    return new Promise((resolve, reject) => {
      if (this.publicAccessConfiguration !== undefined) {
        return resolve(this.publicAccessConfiguration)
      }

      this.s3.getPublicAccessBlock(this.requestProperties, (error: AWSError, data: S3.Types.GetPublicAccessBlockOutput) => {
        if (error !== null && error.code !== 'NoSuchPublicAccessBlockConfiguration') {
          return reject(error)
        }

        const defaultConfig: S3Audit.Types.PublicAccessBlockConfiguration = {
          BlockPublicAcls: false,
          BlockPublicPolicy: false,
          RestrictPublicBuckets: false,
          IgnorePublicAcls: false
        }

        this.publicAccessConfiguration = (data === null) ? defaultConfig
          : Object.assign(defaultConfig, data.PublicAccessBlockConfiguration)

        resolve(this.publicAccessConfiguration)
      })
    })
  }

  public async getPolicyWildcardEntities(): Promise<any> {
    return new Promise((resolve, reject) => {
      this.s3.getBucketPolicy(this.requestProperties, (error: AWSError, data: S3.Types.GetBucketPolicyOutput) => {
        if (error !== null && error.code !== 'NoSuchBucketPolicy') {
          return reject(error)
        }

        if (data === null || data.Policy === undefined) {
          return resolve([])
        }

        const policy = JSON.parse(data.Policy)
        const statements = []

        for (let statement of policy.Statement) {
          if (statement.Effect === 'Deny') {
            continue
          }

          if (statement.Principal === '*' || statement.Principal.AWS === '*') {
            statements.push(statement)

            continue
          }

          if (Array.isArray(statement.Principal.AWS)) {
            const index = statement.Principal.AWS.indexOf('*')

            if (index > -1) {
              statements.push(statement.Principal.AWS[index])
            }
          }

          if (statement.Action === '*') {
            statements.push(statement)

            continue
          }

          if (Array.isArray(statement.Action)) {
            const index = statement.Action.indexOf('*')

            if (index > -1) {
              statements.push(statement.Action[index])
            }
          }
        }

        resolve(statements)
      })
    })
  }

  public async getSSEAlgorithm(): Promise<any> {
    return new Promise((resolve, reject) => {
      this.s3.getBucketEncryption(this.requestProperties, (error: AWSError, data: S3.Types.GetBucketEncryptionOutput) => {
        if (error !== null && error.code !== 'ServerSideEncryptionConfigurationNotFoundError') {
          return reject(error)
        }

        if (data === null || data.ServerSideEncryptionConfiguration === undefined || data.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault === undefined) {
          return resolve(null)
        }

        const algorithm = data.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm

        resolve(algorithm)
      })
    })
  }

  public async hasMFADeleteEnabled(): Promise<any> {
    return new Promise((resolve, reject) => {
      this.getBucketVersioning()
        .then((data: S3.Types.GetBucketVersioningOutput) => {
          if (data === null || data.MFADelete !== 'Enabled') {
            return resolve(false)
          }

          resolve(true)
        })
        .catch((error: AWSError) => {
          reject(error)
        })
    })
  }

  public async hasStaticWebsiteHosting(): Promise<any> {
    return new Promise((resolve, reject) => {
      this.s3.getBucketWebsite(this.requestProperties, (error: AWSError, data: S3.Types.GetBucketWebsiteOutput) => {
        if (error !== null && error.code !== 'NoSuchWebsiteConfiguration') {
          return reject(error)
        }

        if (data === null) {
          return resolve(false)
        }

        resolve(true)
      })
    })
  }

  public async hasVersioningEnabled(): Promise<any> {
    return new Promise((resolve, reject) => {
      this.getBucketVersioning()
        .then((data: S3.Types.GetBucketVersioningOutput) => {
          if (data === null || data.Status !== 'Enabled') {
            return resolve(false)
          }

          resolve(true)
        })
        .catch((error: AWSError) => {
          reject(error)
        })
    })
  }

  public async getLoggingTargetBucket(): Promise<any> {
    return new Promise((resolve, reject) => {
      this.s3.getBucketLogging(this.requestProperties, (error: AWSError, data: S3.Types.GetBucketLoggingOutput) => {
        if (error !== null) {
          return reject(error)
        }

        if (data === null || data.LoggingEnabled === undefined) {
          return resolve(null)
        }

        if (data.LoggingEnabled.TargetBucket) {
          return resolve(data.LoggingEnabled.TargetBucket)
        }

        resolve(null)
      })
    })
  }

  private async getBucketVersioning(): Promise<S3.Types.GetBucketVersioningOutput> {
    return new Promise((resolve, reject) => {
      if (this.bucketVersioning !== undefined) {
        return resolve(this.bucketVersioning)
      }

      this.s3.getBucketVersioning(this.requestProperties, (error: AWSError, data: S3.Types.GetBucketVersioningOutput) => {
        if (error !== null) {
          return reject(error)
        }

        this.bucketVersioning = data

        resolve(data)
      })
    })
  }
}
