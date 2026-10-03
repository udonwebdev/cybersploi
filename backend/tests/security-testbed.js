/**
 * Isolated Security Testbed for CyberSploi Authorized Assessment Testing
 * Provides an authorized, locally controlled testing environment with intentional security conditions:
 * - Real HTTP listeners
 * - Real TCP service listeners
 * - Real security header deficiencies
 * - Real credential/cookie attributes
 * - Real false-positive condition vs. true finding condition
 */

const http = require('http');
const net = require('net');

class SecurityTestbed {
  constructor(httpPort = 8899, tcpPort = 8898) {
    this.httpPort = httpPort;
    this.tcpPort = tcpPort;
    this.httpServer = null;
    this.tcpServer = null;
  }

  start() {
    return new Promise((resolve, reject) => {
      // 1. TCP Server (Admin service listener)
      this.tcpServer = net.createServer((socket) => {
        socket.on('error', () => {});
        socket.write('SSH-2.0-OpenSSH_8.9p1 AuthorizedTestbed\r\n');
        socket.on('data', (d) => {
          try {
            socket.write('Authentication required\r\n');
          } catch (e) {}
        });
      });

      this.tcpServer.listen(this.tcpPort, '127.0.0.1', () => {
        // 2. HTTP Server
        this.httpServer = http.createServer((req, res) => {
          req.on('error', () => {});
          res.on('error', () => {});
          const url = req.url || '/';

          // HTTP TRACE method support for testing method auditing & XST
          if (req.method === 'TRACE') {
            res.writeHead(200, {
              'Content-Type': 'message/http',
              'Server': 'nginx/1.24.0 (Ubuntu)',
              'X-Powered-By': 'Express'
            });
            res.end(`TRACE ${url} HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: CyberSploi\r\n\r\n`);
            return;
          }

          // CORS header reflection check
          const origin = req.headers['origin'];
          if (origin) {
            res.setHeader('Access-Control-Allow-Origin', origin);
            res.setHeader('Access-Control-Allow-Credentials', 'true');
          }

          // Tech stack headers
          res.setHeader('Server', 'nginx/1.24.0 (Ubuntu)');
          res.setHeader('X-Powered-By', 'Express');

          if (url === '/.env') {
            // Genuine Sensitive Finding: Exposed environment secrets
            res.writeHead(200, { 'Content-Type': 'text/plain' });
            res.end('DB_PASSWORD=test_secret_root_pass_2026\nAPP_KEY=base64:TestKey9876543210=\n');
            return;
          }

          if (url === '/benign-page') {
            // False-Positive Trap: Returns 200 OK with ordinary HTML. Must NOT be marked as secret disclosure!
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end('<!DOCTYPE html><html><body><h1>Welcome to Portal</h1><p>Public diagnostic portal</p></body></html>');
            return;
          }

          if (url === '/api/v1/auth/login') {
            // Cookie without HttpOnly attribute
            res.setHeader('Set-Cookie', ['session_id=test_tok_991823; Path=/; SameSite=Lax']);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ status: 'ready', method: 'POST' }));
            return;
          }

          if (url === '/robots.txt') {
            res.writeHead(200, { 'Content-Type': 'text/plain' });
            res.end('User-agent: *\nDisallow: /admin\nDisallow: /internal\n');
            return;
          }

          if (url === '/admin') {
            // Protected administrative path
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Unauthorized', message: 'Authentication required' }));
            return;
          }

          if (url === '/products') {
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end('<!DOCTYPE html><html><body><h2>Products</h2><a href="/pricing">Pricing</a><a href="/privacy">Privacy</a></body></html>');
            return;
          }

          if (url === '/about') {
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end('<!DOCTYPE html><html><body><h2>About Us</h2><a href="/contact">Contact</a></body></html>');
            return;
          }

          if (url === '/pricing') {
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end('<!DOCTYPE html><html><body><h2>Pricing Plans</h2><p>Enterprise grade.</p></body></html>');
            return;
          }

          if (url === '/contact') {
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end('<!DOCTYPE html><html><body><form action="/contact/submit" method="POST"><input name="subject"/><input name="msg"/></form></body></html>');
            return;
          }

          if (url === '/static/bundle.js') {
            res.writeHead(200, { 'Content-Type': 'application/javascript' });
            res.end('console.log("CyberSploi Bundle"); fetch("/api/v1/telemetry"); axios.get("/api/v2/metrics");');
            return;
          }

          if (url === '/static/bundle.js.map') {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
              version: 3,
              file: 'bundle.js',
              sources: ['src/index.ts', 'src/auth.ts', 'src/api.ts'],
              mappings: 'AAAA,SAAS,CAAC...'
            }));
            return;
          }

          if (url === '/api/v1/debug/error') {
            // Verbose error disclosure
            res.writeHead(500, { 'Content-Type': 'text/plain' });
            res.end('Error: Database connection failed\n    at pg.Pool.connect (/app/node_modules/pg/pool.js:14:28)\n    at Query.execute (/app/server.js:88:12)');
            return;
          }

          // Default Root response with deliberate omission of security headers (No HSTS, No CSP, No X-Frame-Options)
          // Includes crawler targets and forms
          res.writeHead(200, {
            'Content-Type': 'text/html',
          });
          res.end(`<!DOCTYPE html>
<html>
<head><title>Authorized Security Test Target</title></head>
<body>
  <h1>CyberSploi Testbed</h1>
  <nav>
    <a href="/products">Products</a>
    <a href="/about">About Us</a>
    <a href="/api/v1/auth/login">Login</a>
  </nav>
  <form action="/api/v1/feedback" method="POST">
    <input type="text" name="feedback" />
    <input type="email" name="user_email" />
    <button type="submit">Submit</button>
  </form>
  <script src="/static/bundle.js"></script>
</body>
</html>`);
        });

        this.httpServer.listen(this.httpPort, '127.0.0.1', () => {
          console.log(`[SecurityTestbed] HTTP running on 127.0.0.1:${this.httpPort}, TCP on 127.0.0.1:${this.tcpPort}`);
          resolve();
        });
      });

      this.tcpServer.on('error', reject);
      if (this.httpServer) this.httpServer.on('error', reject);
    });
  }

  stop() {
    return new Promise((resolve) => {
      let closed = 0;
      const done = () => {
        closed++;
        if (closed >= 2) resolve();
      };
      if (this.httpServer) this.httpServer.close(done);
      else done();
      if (this.tcpServer) this.tcpServer.close(done);
      else done();
    });
  }
}

module.exports = SecurityTestbed;
