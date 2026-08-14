/**
 * Minimal HTTP-testing helper for route unit tests.
 *
 * This repo has no supertest (and no node-fetch/undici) installed, so route
 * tests mount the Express router under test on a real `express()` app, start
 * it on an ephemeral port via Node's built-in `http` server, and drive it
 * with `http.request`. This exercises the real Express routing/middleware
 * stack (unlike calling handlers directly) without adding a new dependency.
 */
import http from 'http';
import express, { Express } from 'express';

export interface TestResponse {
  status: number;
  body: any;
  headers: http.IncomingHttpHeaders;
  text: string;
}

export class TestServer {
  private server: http.Server;
  private baseUrl: string = '';

  private constructor(server: http.Server) {
    this.server = server;
  }

  static async start(app: Express): Promise<TestServer> {
    const server = http.createServer(app);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const ts = new TestServer(server);
    const addr = server.address();
    if (addr && typeof addr === 'object') {
      ts.baseUrl = `http://127.0.0.1:${addr.port}`;
    }
    return ts;
  }

  async close(): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      this.server.close((err) => (err ? reject(err) : resolve()));
    });
  }

  request(
    method: string,
    path: string,
    opts?: { body?: any; headers?: Record<string, string> }
  ): Promise<TestResponse> {
    return new Promise((resolve, reject) => {
      const payload = opts?.body !== undefined ? JSON.stringify(opts.body) : undefined;
      const headers: Record<string, string> = { ...(opts?.headers ?? {}) };
      if (payload !== undefined) {
        headers['Content-Type'] = 'application/json';
        headers['Content-Length'] = Buffer.byteLength(payload).toString();
      }

      const req = http.request(
        `${this.baseUrl}${path}`,
        { method, headers },
        (res) => {
          let raw = '';
          res.on('data', (chunk) => (raw += chunk));
          res.on('end', () => {
            let body: any = raw;
            const contentType = res.headers['content-type'] ?? '';
            if (contentType.includes('application/json') && raw.length > 0) {
              try {
                body = JSON.parse(raw);
              } catch {
                // leave as raw text if parsing fails
              }
            }
            resolve({
              status: res.statusCode ?? 0,
              body,
              headers: res.headers,
              text: raw,
            });
          });
        }
      );
      req.on('error', reject);
      if (payload !== undefined) req.write(payload);
      req.end();
    });
  }

  get(path: string, headers?: Record<string, string>) {
    return this.request('GET', path, { headers });
  }
  post(path: string, body?: any, headers?: Record<string, string>) {
    return this.request('POST', path, { body, headers });
  }
  put(path: string, body?: any, headers?: Record<string, string>) {
    return this.request('PUT', path, { body, headers });
  }
  patch(path: string, body?: any, headers?: Record<string, string>) {
    return this.request('PATCH', path, { body, headers });
  }
  delete(path: string, headers?: Record<string, string>) {
    return this.request('DELETE', path, { headers });
  }
}

/** Mounts `router` at `mountPath` on a fresh Express app with JSON body parsing. */
export function buildTestApp(mountPath: string, router: express.Router): Express {
  const app = express();
  app.use(express.json());
  app.use(mountPath, router);
  return app;
}

/** Standard fake authenticated header — pairs with the authenticate mock used in route tests. */
export const AUTH_HEADER = { Authorization: 'Bearer test-token' };
