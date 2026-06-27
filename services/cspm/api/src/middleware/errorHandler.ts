import { Request, Response, NextFunction } from 'express';
import { ZodError } from 'zod';
import { logger } from '../config/logger';

export function errorHandler(
  err: Error,
  req: Request,
  res: Response,
  _next: NextFunction
): void {
  logger.error('Unhandled error', {
    error: err.message,
    stack: err.stack,
    path: req.path,
    method: req.method,
  });

  if (err instanceof ZodError) {
    res.status(400).json({
      error: 'Validation error',
      details: err.flatten().fieldErrors,
    });
    return;
  }

  const message = err.message.toLowerCase();

  if (
    message.includes('unauthorized') ||
    message.includes('invalid token') ||
    message.includes('jwt')
  ) {
    res.status(401).json({ error: err.message });
    return;
  }

  if (message.includes('forbidden') || message.includes('not allowed')) {
    res.status(403).json({ error: err.message });
    return;
  }

  if (message.includes('not found')) {
    res.status(404).json({ error: err.message });
    return;
  }

  res.status(500).json({ error: 'Internal server error' });
}

export default errorHandler;
