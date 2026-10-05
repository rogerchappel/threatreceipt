import http from 'node:http';
export async function startFixture(profile) {
  if (!['secure', 'vulnerable'].includes(profile)) throw new Error('Invalid fixture profile.');
  // Synthetic identities and data, never credentials or customer records.
  const record = { id: 'alpha', tenant: 'tenant-a', value: 'synthetic-only' };
  const server = http.createServer((req, res) => {
    const reply = (status, body) => {
      res.writeHead(status, { 'content-type': 'application/json' });
      res.end(JSON.stringify(body));
    };
    if (req.method !== 'GET') return reply(405, { error: 'method' });
    const url = new URL(req.url, 'http://127.0.0.1');
    if (url.pathname !== '/records') return reply(404, { error: 'route' });
    const actor = req.headers['x-demo-actor'];
    const key = url.searchParams.get('id');
    if (profile === 'secure') {
      if (typeof actor !== 'string' || !['tenant-a', 'tenant-b'].includes(actor)) return reply(401, { error: 'auth' });
      if (key !== record.id) return reply(404, { error: 'missing' });
      if (actor !== record.tenant) return reply(403, { error: 'forbidden' });
    }
    // Deliberate flaws: no identity/ownership enforcement and overly broad lookup.
    return reply(200, { records: [record] });
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve(undefined));
  });
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Invalid fixture binding.');
  return {
    origin: `http://127.0.0.1:${address.port}`,
    close: () => new Promise(resolve => { server.closeAllConnections(); server.close(resolve); })
  };
}
