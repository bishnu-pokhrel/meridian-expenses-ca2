const request = require('supertest');

// Seeded test accounts, never real credentials.
const USERS = {
  jdoe:   { username: 'jdoe',   password: 'password1' },   // staff, owns claims 1 and 2
  rsmith: { username: 'rsmith', password: 'letmein' },     // staff, owns claim 3
  achen:  { username: 'achen',  password: 'Summer2026' },  // finance, owns claim 4
  admin:  { username: 'admin',  password: 'admin' },       // admin, owns claim 5
};

async function agentFor(app, who) {
  const agent = request.agent(app);            // keeps cookies between requests
  if (who !== 'anon') {
    await agent.post('/login').type('form').send(USERS[who]);
  }
  return agent;
}

module.exports = { USERS, agentFor };
