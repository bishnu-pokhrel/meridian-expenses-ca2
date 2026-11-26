// Vertical access control / role check on /export (CWE-862, WSTG-ATHZ-02).
// Business rule: only finance and admin may export, and the export returns
// every user's claims as CSV, so ordinary staff must be refused. Written
// from the policy, not the code.
require('./setup');
const { agentFor } = require('./helpers');
const app = require('../../server');

// /export is finance and admin only. Expected HTTP status by caller:
const MATRIX = [
  ['anon',   'get', '/export',   302],  // not logged in -> redirected to login
  ['rsmith', 'get', '/export',   403],  // another staff member -> forbidden
  ['jdoe',   'get', '/export',   403],  // ordinary staff -> forbidden
  ['achen',  'get', '/export',   200],  // finance -> allowed to export
  ['admin',  'get', '/export',   200],  // admin  -> allowed to export
];

describe('vertical access control on /export (CWE-862)', () => {
  test.each(MATRIX)('%s %s %s -> %i', async (who, method, path, expected) => {
    const agent = await agentFor(app, who);
    const res = await agent[method](path);
    expect(res.status).toBe(expected);
  });

  test("a refused request leaks none of the other user's data", async () => {
    const agent = await agentFor(app, 'rsmith');     // ordinary staff, not finance or admin
    const res = await agent.get('/export');          
    expect(res.status).toBe(403);
    expect(res.text).not.toContain('Dublin Coach');  // another user's claim data the export would contain
    expect(res.text).not.toContain('Client visit');  // another user's claim note the export would contain
  });
});
