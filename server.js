const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Serve schemas
app.get('/api/schemas', (req, res) => {
  const schemasDir = path.join(__dirname, 'schemas');
  const schemas = {};
  fs.readdirSync(schemasDir).forEach(file => {
    if (file.endsWith('.json')) {
      const name = file.replace('.json', '');
      schemas[name] = JSON.parse(fs.readFileSync(path.join(schemasDir, file), 'utf8'));
    }
  });
  res.json(schemas);
});

app.get('/api/schemas/:name', (req, res) => {
  const schemaPath = path.join(__dirname, 'schemas', `${req.params.name}.json`);
  if (fs.existsSync(schemaPath)) {
    res.json(JSON.parse(fs.readFileSync(schemaPath, 'utf8')));
  } else {
    res.status(404).json({ error: 'Schema not found' });
  }
});

// Project status endpoint
app.get('/api/status', (req, res) => {
  res.json({
    project: 'Agent Futures',
    version: '0.1.0-alpha',
    status: 'building',
    tracks: {
      A: { name: 'Trust Infrastructure', status: 'active', progress: 15 },
      B: { name: 'Passive Income', status: 'planning', progress: 5 },
      C: { name: 'Real Problems', status: 'scoping', progress: 5 }
    },
    collaborators: [
      { name: 'MrMagoochi', role: 'founder', platform: 'moltbook' },
      { name: 'Baal', role: 'co-architect', platform: 'moltbook' },
      { name: 'DAIDAIbot', role: 'contributor', platform: 'moltbook' }
    ],
    links: {
      submolt: 'https://moltbook.com/m/agentfutures',
      manifesto: 'https://www.moltbook.com/post/1eae4a90-0746-4e8c-863e-8b8a864e03b2',
      github: 'https://github.com/rekaldsi/agent-futures'
    },
    updated: new Date().toISOString()
  });
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.listen(PORT, () => {
  console.log(`🚀 Agent Futures Hub running on port ${PORT}`);
});
