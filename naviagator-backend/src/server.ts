// ============================================
// backend/server.ts (หรือ index.ts)
// ============================================

import express, { Express } from 'express';
import cors from 'cors';
import { router as ctiRouter } from './routes/cti';

const app: Express = express();

// Middleware
app.use(cors());
app.use(express.json());

// Routes
app.use('/api/cti',  ctiRouter);

// เพิ่ม routes อื่นๆ ของคุณ...

const PORT = process.env.PORT || 3001;

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📊 CTI API available at http://localhost:${PORT}/api/cti`);
  console.log(`\nAvailable endpoints:`);
  console.log(`  GET /api/cti/tactics`);
  console.log(`  GET /api/cti/techniques?platform=windows`);
  console.log(`  GET /api/cti/techniques/:id`);
  console.log(`  GET /api/cti/stats`);
});

export default app;