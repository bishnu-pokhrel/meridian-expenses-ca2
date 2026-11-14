// Horizontal access control / IDOR (CWE-639, WSTG-ATHZ-04).
// The matrix is written from the access-control POLICY, not read off the code:
// a claim is private to its owner; finance and admin may view any claim.
require('./setup');
const { agentFor } = require('./helpers');
const app = require('../../server');

// Claim 1 belongs to jdoe (staff). Expected HTTP status by caller:
const MATRIX = [
  ['anon',   'get', '/claim/1',   302],  // not logged in -> redirected to login
  ['rsmith', 'get', '/claim/1',   403],  // another staff member -> forbidden
  ['jdoe',   'get', '/claim/1',   200],  // the owner -> allowed
  ['achen',  'get', '/claim/1',   200],  // finance -> may view any
  ['admin',  'get', '/claim/1',   200],  // admin  -> may view any
  ['jdoe',   'get', '/claim/999', 404],  // does not exist
];

describe('horizontal access control on /claim/:id (CWE-639)', () => {
  test.each(MATRIX)('%s %s %s -> %i', async (who, method, path, expected) => {
    const agent = await agentFor(app, who);
    const res = await agent[method](path);
    expect(res.status).toBe(expected);
  });

  test("a refused request leaks none of the other user's data", async () => {
    const agent = await agentFor(app, 'rsmith');     // not the owner of claim 1
    const res = await agent.get('/claim/1');
    expect(res.status).toBe(403);
    expect(res.text).not.toContain('Dublin Coach');  // jdoe's claim-1 merchant
    expect(res.text).not.toContain('Client visit');  // jdoe's claim-1 note
  });
});
