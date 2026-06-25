export default function handler(req, res) { res.statusCode = 200; res.setHeader('content-type','text/plain'); res.end('pong-esm ' + process.version); }
