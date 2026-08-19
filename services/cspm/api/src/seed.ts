import { prisma } from './config/database';
import * as authService from './services/authService';
import { env } from './config/env';
import { logger } from './config/logger';

export async function seed(): Promise<void> {
  const userCount = await prisma.user.count();

  if (userCount === 0) {
    logger.info('No users found, creating admin user...');

    const passwordHash = await authService.hashPassword(env.ADMIN_PASSWORD);

    const admin = await prisma.user.create({
      data: {
        email: env.ADMIN_EMAIL,
        passwordHash,
        role: 'ADMIN',
      },
    });

    logger.info(`Admin user created: ${admin.email}`);
  } else {
    logger.info(`Database already has ${userCount} user(s), skipping seed`);
  }
}

if (require.main === module) {
  seed()
    .then(() => {
      logger.info('Seed completed');
      process.exit(0);
    })
    .catch((err) => {
      logger.error('Seed failed', { error: err.message });
      process.exit(1);
    })
    .finally(async () => {
      await prisma.$disconnect();
    });
}
