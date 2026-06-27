import { Server } from 'socket.io';
import { Server as HTTPServer } from 'http';
import { logger } from '../config/logger';

let io: Server;

export function initSocket(server: HTTPServer): Server {
  io = new Server(server, {
    cors: {
      origin: process.env.CORS_ORIGIN || 'http://localhost:5173',
      methods: ['GET', 'POST'],
    },
  });

  io.on('connection', (socket) => {
    logger.debug(`Socket connected: ${socket.id}`);

    socket.on('subscribe:scan', ({ scanId }: { scanId: string }) => {
      socket.join(`scan:${scanId}`);
      logger.debug(`Socket ${socket.id} subscribed to scan:${scanId}`);
    });

    socket.on('unsubscribe:scan', ({ scanId }: { scanId: string }) => {
      socket.leave(`scan:${scanId}`);
      logger.debug(`Socket ${socket.id} unsubscribed from scan:${scanId}`);
    });

    // ── Threat monitoring rooms ───────────────────────────────────────────────
    socket.on('threats:subscribe', ({ accountId }: { accountId: string }) => {
      socket.join(`threats:${accountId}`);
      logger.debug(`Socket ${socket.id} subscribed to threats:${accountId}`);
    });

    socket.on('threats:unsubscribe', ({ accountId }: { accountId: string }) => {
      socket.leave(`threats:${accountId}`);
      logger.debug(`Socket ${socket.id} unsubscribed from threats:${accountId}`);
    });

    socket.on('threats:subscribe:all', () => {
      socket.join('threats:all');
      logger.debug(`Socket ${socket.id} subscribed to threats:all`);
    });

    socket.on('threats:unsubscribe:all', () => {
      socket.leave('threats:all');
    });

    // ── Config change sync rooms ──────────────────────────────────────────────
    socket.on('config-changes:subscribe', ({ provider, targetId }: { provider: string; targetId: string }) => {
      const room = `config-changes:${provider}:${targetId}`;
      socket.join(room);
      socket.join('config-changes:all');
      logger.debug(`Socket ${socket.id} subscribed to ${room}`);
    });

    socket.on('config-changes:unsubscribe', ({ provider, targetId }: { provider: string; targetId: string }) => {
      socket.leave(`config-changes:${provider}:${targetId}`);
    });

    socket.on('disconnect', () => {
      logger.debug(`Socket disconnected: ${socket.id}`);
    });
  });

  return io;
}

export function getIO(): Server {
  if (!io) {
    throw new Error('Socket.IO not initialized');
  }
  return io;
}
