/**
 * Shared helper for route-level tests.
 *
 * This repo has no supertest (and no node-fetch/undici) installed, so route
 * tests mount the router under test on a minimal Express app, start it on an
 * ephemeral port via Node's built-in http server, and drive it with Node 18's
 * built-in global `fetch`. `close()` tears the server down after each test.
 */
import express, { Router } from 'express';
import type { AddressInfo } from 'net';

export interface TestServer {
  baseUrl: string;
  close: () => Promise<void>;
}

export async function startTestServer(mountPath: string, router: Router): Promise<TestServer> {
  const app = express();
  app.use(express.json());
  app.use(mountPath, router);

  const server = app.listen(0);
  await new Promise<void>((resolve) => server.once('listening', resolve));
  const { port } = server.address() as AddressInfo;

  return {
    baseUrl: `http://127.0.0.1:${port}${mountPath}`,
    close: () => new Promise<void>((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()));
    }),
  };
}
