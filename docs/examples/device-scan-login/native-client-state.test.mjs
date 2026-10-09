// No-network state check for unknown-result close-origin recovery.
import assert from 'node:assert/strict';
import { originForVerification, prepareFlow, recordClosedOrigin } from './native-client-state.mjs';

const pending = {
  flow: 'claim', delivery_secret: 'origin-secret', claim_operation_id: 'claim-op',
  grant_id: 'grant', exchange_operation_id: 'issuance-op', ack_operation_id: 'ack-op',
  delivery: { receipt_nonce: 'receipt', tokens: { refresh_token: 'refresh' } },
};
assert.equal(prepareFlow(pending, 'claim', pending.delivery_secret, 'claim-op'), pending);
assert.throws(() => prepareFlow(pending, 'create', 'new-secret', 'new-create-op'), /close the existing/);
const sent = [];
async function mockClose(origin, outcome) {
  sent.push(origin);
  if (outcome === 'lost_response') throw new Error('synthetic response loss');
  return { outcome };
}

// A lost close response does not mutate state, so the same scoped close retries.
let state = structuredClone(pending);
const origin = originForVerification(state);
await assert.rejects(mockClose(origin, 'lost_response'), /response loss/);
assert.deepEqual(originForVerification(state), origin);
assert.equal((await mockClose(originForVerification(state), 'closed')).outcome, 'closed');
state = recordClosedOrigin(state, origin, 'origin-hash');
assert.deepEqual(sent, [origin, origin]);
assert.deepEqual(originForVerification(state), { ...origin, delivery_secret_hash: 'origin-hash' });
assert.equal('delivery' in state, false);
assert.equal('ack_operation_id' in state, false);
assert.equal(JSON.stringify(state).includes('receipt'), false);
assert.equal(JSON.stringify(state).includes('refresh'), false);

// A later create gets a new operation and secret; the closed one stays read-only.
const next = prepareFlow(state, 'create', 'new-secret', 'new-create-op');
assert.equal(next.create_operation_id, 'new-create-op');
assert.equal(next.delivery_secret, 'new-secret');
assert.deepEqual(originForVerification(next), { action: 'create', operation_id: 'new-create-op', delivery_secret: 'new-secret' });
assert.equal('origin_closed' in next, false);
assert.throws(() => prepareFlow(state, 'claim', 'new-secret', 'claim-op'), /cannot be reused/);

// already_activated does not discard the active delivery bundle.
const activated = structuredClone(pending);
assert.equal((await mockClose(originForVerification(activated), 'already_activated')).outcome, 'already_activated');
assert.deepEqual(activated.delivery, pending.delivery);
console.log('native scan close-origin state transitions passed');
