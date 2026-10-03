import * as http from 'http';

export class MockTargetServer {
  private server: http.Server | null = null;
  public port: number = 0;
  private flakyCounter: number = 0;

  public async start(): Promise<number> {
    return new Promise((resolve, reject) => {
      this.server = http.createServer((req, res) => {
        const url = req.url || '/';
        const role = req.headers['x-role'] as string;
        const tenant = req.headers['x-tenant'] as string;

        // Route: /public/status
        if (url === '/public/status') {
          res.writeHead(200, {
            'Content-Type': 'application/json',
            'X-Frame-Options': 'DENY',
            'Content-Security-Policy': "default-src 'self'"
          });
          res.end(JSON.stringify({ status: 'OK', public: true }));
          return;
        }

        // Route: /admin/sensitive (Vertical Authorization test)
        if (url === '/admin/sensitive') {
          if (role === 'admin') {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ secret: 'ADMIN_SECRET_KEY_123', accessible: true }));
          } else {
            res.writeHead(403, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'FORBIDDEN', message: 'Admin role required' }));
          }
          return;
        }

        // Route: /tenant/a/data (Horizontal Authorization test)
        if (url === '/tenant/a/data') {
          if (tenant === 'tenant_a') {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ tenant: 'tenant_a', data: 'CONFIDENTIAL_A' }));
          } else {
            res.writeHead(403, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'FORBIDDEN', message: 'Tenant isolation boundary' }));
          }
          return;
        }

        // Route: /tenant/b/data (Horizontal Authorization test)
        if (url === '/tenant/b/data') {
          if (tenant === 'tenant_b') {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ tenant: 'tenant_b', data: 'CONFIDENTIAL_B' }));
          } else {
            res.writeHead(403, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'FORBIDDEN', message: 'Tenant isolation boundary' }));
          }
          return;
        }

        // Route: /api/flaky (Fails 2 times with 500, then returns 200)
        if (url === '/api/flaky') {
          this.flakyCounter++;
          if (this.flakyCounter < 3) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'TRANSIENT_FAILURE', attempt: this.flakyCounter }));
          } else {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: true, attempt: this.flakyCounter }));
          }
          return;
        }

        // Route: /api/slow (Simulates high latency)
        if (url.startsWith('/api/slow')) {
          const delay = 1500;
          setTimeout(() => {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ delayed: true, ms: delay }));
          }, delay);
          return;
        }

        // Default 200 for other endpoints
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ target: 'mock', path: url }));
      });

      this.server.listen(0, '127.0.0.1', () => {
        const address = this.server!.address() as any;
        this.port = address.port;
        resolve(this.port);
      });

      this.server.on('error', (err) => reject(err));
    });
  }

  public async stop(): Promise<void> {
    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => resolve());
      } else {
        resolve();
      }
    });
  }
}
