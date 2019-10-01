import {S3} from 'aws-sdk'

import {S3Audit} from './@types'

export default class Bucket {
  public name: string
  private requestProperties: S3Audit.Types.S3RequestProperties
  private s3: S3

  constructor(name: string) {
    this.name = name
    this.requestProperties = {Bucket: this.name}
    this.s3 = new S3()
  }

  public async checkBucketACL(): Promise<any> {
    return new Promise((resolve, reject) => {
      this.s3.getBucketAcl(this.requestProperties, (error: Object, data: S3.Types.GetBucketAclOutput) => {
        if (data === null || ! Array.isArray(data.Grants) || data.Grants.length === 0) {
          return resolve()
        }

        for (let grant of data.Grants) {
          if (grant.Grantee === undefined || grant.Grantee.Type !== 'Group' || grant.Grantee.URI === undefined) {
            continue
          }

          // tslint:disable-next-line:no-http-string
          if (['http://acs.amazonaws.com/groups/global/AllUsers', 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'].includes(grant.Grantee.URI)) {
            return reject('Bucket ACL allows public access')
          }
        }

        resolve()
      })
    })
  }

  public async checkBucketWebsite(): Promise<any> {
    return new Promise((resolve, reject) => {
      this.s3.getBucketWebsite(this.requestProperties, (error: Object, data: S3.Types.GetBucketWebsiteOutput) => {
        if (data === null) {
          return resolve()
        }

        reject(new Error('Bucket has static website hosting enabled'))
      })
    })
  }

  public async checkBucketVersioning(): Promise<any> {
    return new Promise((resolve, reject) => {
      this.s3.getBucketVersioning(this.requestProperties, (error: Object, data: S3.Types.GetBucketVersioningOutput) => {
        if (data === null || data.Status !== 'Enabled') {
          return reject()
        }

        return resolve()
      })
    })
  }

  public async checkEncryptionIsEnabled(): Promise<any> {
    return new Promise((resolve, reject) => {
      this.s3.getBucketEncryption(this.requestProperties, (error: Object, data: S3.Types.GetBucketEncryptionOutput) => {
        if (data === null || data.ServerSideEncryptionConfiguration === undefined || data.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault === undefined) {
          return reject()
        }

        const algorithm = data.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm

        resolve(`Bucket encryption algorithm is: ${algorithm}`)
      })
    })
  }

  public async checkPublicAccess(): Promise<any> {
    return new Promise((resolve, reject) => {
      this.s3.getPublicAccessBlock(this.requestProperties, (error: Object, data: S3.Types.GetPublicAccessBlockOutput) => {
        const defaultConfig: S3Audit.Types.PublicAccessBlockConfiguration = {
          BlockPublicAcls: false,
          BlockPublicPolicy: false,
          RestrictPublicBuckets: false,
          IgnorePublicAcls: false
        }

        if (data === null) {
          return resolve(defaultConfig)
        }

        resolve(Object.assign(defaultConfig, data.PublicAccessBlockConfiguration))
      })
    })
  }

  public async checkThatBucketPolicyDoesntAllowWildcardEntity(): Promise<any> {
    return new Promise((resolve, reject) => {
      this.s3.getBucketPolicy(this.requestProperties, (error: Object, data: S3.Types.GetBucketPolicyOutput) => {
        if (data === null || data.Policy === undefined) {
          return resolve()
        }

        const policy = JSON.parse(data.Policy)

        for (let statement of policy.Statement) {
          if (statement.Effect === 'Deny') {
            continue
          }

          if (statement.Principal === '*') {
            return reject(`Statement ${statement.Sid} allows a wildcard principal`)
          }

          if (Array.isArray(statement.Principal)) {
            for (let principal of statement.Principal) {
              if (principal === '*') {
                return reject(`Statement ${statement.Sid} allows a wildcard principal`)
              }
            }
          }

          if (statement.Action === '*') {
            return reject(`Statement ${statement.Sid} allows a wildcard action`)
          }

          if (Array.isArray(statement.Action)) {
            for (let action of statement.Action) {
              if (action === '*') {
                return reject(`Statement ${statement.Sid} allows a wildcard action`)
              }
            }
          }
        }

        resolve()
      })
    })
  }
}
