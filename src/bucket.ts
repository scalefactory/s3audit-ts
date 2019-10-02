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

          if (statement.Principal === '*') {
            statements.push(statement)

            continue
          }

          if (Array.isArray(statement.Principal)) {
            for (let principal of statement.Principal) {
              if (principal === '*') {
                statements.push(statement)

                continue
              }
            }
          }

          if (statement.Action === '*') {
            statements.push(statement)

            continue
          }

          if (Array.isArray(statement.Action)) {
            for (let action of statement.Action) {
              if (action === '*') {
                statements.push(statement)

                continue
              }
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
