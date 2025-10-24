// server/proxy.js
import express from 'express';
import cors from 'cors';
import fetch from 'node-fetch';  

const app = express();

// เพิ่ม CORS middleware ก่อน express.json()
app.use(cors({
  origin: 'http://localhost:5173', // Vite default port
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

app.use(express.json());

const ES_URL = process.env.ES_URL || 'http://localhost:9200';
const ES_USER = process.env.ES_USER || '';      // ถ้ามี auth
const ES_PASS = process.env.ES_PASS || '';

app.post('/api/search', async (req, res) => {
  try {
    const esPath = req.query.index ? `/${req.query.index}/_search` : '/_search';
    const url = `${ES_URL}${esPath}`;
    
    console.log('Proxying request to:', url);
    console.log('Request body:', JSON.stringify(req.body, null, 2));
    
    const opts = {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(req.body),
    };
    
    if (ES_USER && ES_PASS) {
      const token = Buffer.from(`${ES_USER}:${ES_PASS}`).toString('base64');
      opts.headers['Authorization'] = `Basic ${token}`;
    }
    
    const r = await fetch(url, opts);
    const json = await r.json();
    
    console.log('ES Response status:', r.status);
    console.log('ES Response hits:', json.hits?.total);
    
    res.status(r.status).json(json);
  } catch (err) {
    console.error('Proxy error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Proxy server listening on port ${PORT}`);
  console.log(`Elasticsearch URL: ${ES_URL}`);
  console.log(`CORS enabled for: http://localhost:5173`);
});