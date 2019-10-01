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
}
