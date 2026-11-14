// Workflow integrity / self-approval (CWE-841, WSTG-BUSL-06).
// Business rule: only finance or admin may approve a claim, and nobody may
// approve their own. Written from the policy, not the code.
require('./setup');
const { agentFor } = require('./helpers');
const app = require('../../server');

describe('claim approval workflow (CWE-841)', () => {
  test('finance cannot approve their OWN claim (self-approval blocked)', async () => {
    const agent = await agentFor(app, 'achen');       // achen owns claim 4
    const res = await agent.post('/claim/4/approve');
    expect(res.status).toBe(403);
    expect(res.text).toMatch(/your own claim/i);
  });

  test("finance CAN approve another user's pending claim", async () => {
    const agent = await agentFor(app, 'achen');
    const res = await agent.post('/claim/1/approve'); // claim 1 belongs to jdoe
    expect(res.status).toBe(302);                     // approved -> redirect
  });

  test('a normal staff member cannot approve at all (vertical control)', async () => {
    const agent = await agentFor(app, 'rsmith');
    const res = await agent.post('/claim/2/approve');
    expect(res.status).toBe(403);                     // requireRole blocks it
  });

  test('an anonymous visitor cannot approve', async () => {
    const agent = await agentFor(app, 'anon');
    const res = await agent.post('/claim/2/approve');
    expect(res.status).toBe(302);                     // redirected to login
  });
});
