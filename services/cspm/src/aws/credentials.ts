import AWSClient from './client';
import logger from '../utils/logger';

export class CredentialsManager {
  static validateCredentials(): boolean {
    const hasEnv = process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY;
    const hasProfile = process.env.AWS_PROFILE;
    
    if (!hasEnv && !hasProfile) {
      logger.error('No AWS credentials found. Set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY or AWS_PROFILE');
      return false;
    }

    return true;
  }

  static getProfile(): string | undefined {
    return process.env.AWS_PROFILE;
  }

  static validateAndCreateClient(
    region: string = process.env.AWS_REGION || 'us-east-1',
    profile?: string
  ): AWSClient {
    if (!this.validateCredentials()) {
      throw new Error('Invalid AWS credentials configuration');
    }

    return new AWSClient(region, profile || this.getProfile());
  }

  static supportsAssumeRole(): boolean {
    return !!process.env.AWS_ROLE_ARN;
  }

  static getRoleArn(): string | undefined {
    return process.env.AWS_ROLE_ARN;
  }
}

export default CredentialsManager;
