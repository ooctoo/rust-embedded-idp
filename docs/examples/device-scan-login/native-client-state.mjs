// Stateful rules shared by the executable example and its no-network check.
export function originForVerification(state) {
  if (state.flow === 'closed' && state.origin_closed) return state.origin_closed;
  if (state.flow === 'create' && state.create_operation_id && state.delivery_secret) {
    return { action: 'create', operation_id: state.create_operation_id, delivery_secret: state.delivery_secret };
  }
  if (state.flow === 'claim' && state.claim_operation_id && state.delivery_secret) {
    return { action: 'claim', operation_id: state.claim_operation_id, delivery_secret: state.delivery_secret };
  }
  throw new Error('no original create or claim operation id');
}

export function prepareFlow(state, action, deliverySecret, operationId) {
  const operationField = action === 'create' ? 'create_operation_id' : 'claim_operation_id';
  if (state.flow === action) {
    if (state[operationField] !== operationId || state.delivery_secret !== deliverySecret) {
      throw new Error('same flow must retain its original operation ID and delivery secret');
    }
    return state;
  }
  if (state.flow && state.flow !== 'closed') {
    throw new Error('close the existing original operation before starting the other flow');
  }
  if (state.origin_closed?.action === action && state.origin_closed.operation_id === operationId) {
    throw new Error('a closed origin operation ID cannot be reused');
  }
  // Starting another origin has no pending delivery or closed-origin state to carry.
  return { flow: action, delivery_secret: deliverySecret, [operationField]: operationId };
}

export function recordClosedOrigin(state, origin, deliverySecretHash) {
  // The old secret remains only in the closed-origin record for idempotent lookup
  // or close confirmation. Pending delivery material must not survive a close.
  const { delivery, grant_id, exchange_operation_id, ack_operation_id,
    cancel_operation_id, abort_operation_id, delivery_secret, ...rest } = state;
  return {
    ...rest,
    flow: 'closed',
    origin_closed: { ...origin, delivery_secret_hash: deliverySecretHash },
  };
}
