module.exports = (req, res) => { res.statusCode = 200; res.setHeader('content-type','text/plain'); res.end('pong-cjs ' + process.version); };
