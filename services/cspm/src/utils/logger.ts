import winston from 'winston';

const logLevel = process.env.LOG_LEVEL || 'info';

const logger = winston.createLogger({
  level: logLevel,
  format: winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.errors({ stack: true }),
    winston.format.printf(({ level, message, timestamp, ...meta }) => {
      const metaStr = Object.keys(meta).length ? JSON.stringify(meta) : '';
      return `${timestamp} [${level.toUpperCase()}]: ${message} ${metaStr}`;
    })
  ),
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.printf(({ level, message, ...meta }) => {
          const metaStr = Object.keys(meta).length
            ? ' ' + JSON.stringify(meta)
            : '';
          return `[${level}] ${message}${metaStr}`;
        })
      )
    }),
    new winston.transports.File({
      filename: 'aws-scanner.log',
      maxsize: 10485760, // 10MB
      maxFiles: 5
    })
  ]
});

export default logger;
