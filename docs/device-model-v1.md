# Device Model v1

## Purpose

This document defines the device domain model and registration flows for `rust-embedded-idp`.

It resolves two concrete requirements:

1. provision a device before any user logs in, then complete registration later
2. optionally attach that active device to an auth session during register or login

It also clarifies how the module should behave when multiple users use the same physical device.

## Problem Statement

The earlier device model treated a `DeviceRecord` as if it always belonged to exactly one account.

That model is too restrictive because:

- a physical device may exist before any user logs in
- a shared device may be used by multiple accounts over time
- logging out should revoke a session, not destroy the device identity itself

So the module must distinguish:

- the physical device
- the relationship between an account and a device
- the auth session created during login

## Domain Split

### `DeviceRecord`

Represents the physical device itself.

Fields:

- `id`
- `client_id`
- `device_name`
- `proof_key_id`
- `status`
- `registered_at`
- `last_seen_at`

This object does not directly own `account_id`.

### `AccountDeviceBinding`

Represents the relationship between one account and one device.

Fields:

- `id`
- `account_id`
- `device_id`
- `status`
- `bound_at`
- `unbound_at`
- `last_authenticated_at`

This allows:

- one device to be bound to one account
- one device to be bound to multiple accounts over time
- binding history to remain stable even if sessions are revoked

### `DeviceNonce`

Represents a short-lived bootstrap challenge used during device provisioning or replay protection.

Fields:

- `id`
- `device_id`
- `challenge`
- `issued_at`
- `expires_at`
- `consumed_at`

## Device Status

### `DeviceStatus`

- `Pending`
- `Active`
- `Disabled`
- `Revoked`

Meaning:

- `Pending`: a device shell exists but registration is not fully completed
- `Active`: the device has completed proof validation and can heartbeat or bind
- `Disabled`: temporarily blocked by host policy
- `Revoked`: permanently rejected or retired

### `AccountDeviceBindingStatus`

- `Active`
- `Unbound`
- `Suspended`

Meaning:

- `Active`: the account currently trusts this device binding
- `Unbound`: a prior binding existed and was intentionally removed
- `Suspended`: the binding still exists historically but is not currently trusted

## Registration Flow

### Canonical Flow: Provision First, Complete Later

Use this when the device must exist before login or before any account context is available.

Steps:

1. `provision_device`
   - create a `Pending` device
   - create a short-lived `DeviceNonce`
   - return `device_id` and challenge
2. `complete_device_registration`
   - caller provides `device_id + proof`
   - the bootstrap challenge is carried in `proof.challenge`
   - module verifies challenge and proof
   - module consumes the nonce
   - device becomes `Active`
3. optional account linkage
   - later, after user login or registration, either:
   - call `bind_device_to_account`
   - or let `register_account` / `login` consume `device_id` and auto-create or refresh the active binding

Result:

- the device can be registered without a logged-in account
- account binding becomes a later authenticated step

## Shared Device Behavior

The module domain should support multiple accounts using the same device over time.

So:

- `DeviceRecord` remains stable across logins and logouts
- `AccountDeviceBinding` tracks which accounts trust or used the device
- `logout` revokes the auth session only
- logging in as another user should create or update bindings, not overwrite the device object

## Policy Boundary

The module data model supports shared devices by default.

Host policy may later choose either:

- `shared_device`
  - multiple active bindings may exist for one device
- `exclusive_device`
  - only one active binding may exist at a time

This policy decision should stay outside the base device entity model.

In the current implementation slice, the module should support `shared_device` semantics by default.

## Session Boundary for This Slice

`AuthSession.device_id` is optional.

Meaning:

- login and account registration do not require a device
- if the caller submits `device_id`, the module validates the active device and same `client_id`
- on success the module links the session to that device and refreshes or creates the active account-device binding
- if the caller omits `device_id`, the session remains device-agnostic

## Core Service Target

`DeviceService` should provide:

- `provision_device`
- `complete_device_registration`
- `bind_device_to_account`
- `get_device`
- `list_devices`
- `unbind_device_from_account`
- `disable_device`
- `revoke_device`
- `heartbeat`

## HTTP Surface Target

Fixed routes should evolve to:

- `POST /devices/provision`
- `POST /devices/complete`
- `POST /devices/bind`
- `GET /devices`
- `GET /devices/:device_id`
- `POST /devices/unbind`
- `POST /devices/heartbeat`
- `POST /admin/devices/disable`
- `POST /admin/devices/revoke`

Meaning:

- `/provision`: create pending device and challenge
- `/complete`: finish proof-based registration of a provisioned device
- `/bind`: attach an active device to an account
- `/devices`: list devices, optionally filtered by current account context or explicit `account_id`
- `/devices/:device_id`: fetch one device and its bindings
- `/unbind`: remove the account-device relationship without deleting the device
- `/heartbeat`: update last-seen for an active device
- `/admin/devices/disable`: temporarily block a device from active use through an admin-only route
- `/admin/devices/revoke`: permanently retire a device through an admin-only route

## Management Semantics

Management operations should preserve the separation between `device` and `binding`.

### Query

`get_device` returns:

- the `DeviceRecord`
- related `AccountDeviceBinding` rows for that device

`list_devices` returns:

- all devices when no account filter is provided
- devices currently actively bound to an account when `account_id` is provided

This keeps the list endpoint useful both for host administration and for "my devices" style account views.

### Unbind

`unbind_device_from_account` changes the binding, not the device.

Expected effect:

- locate the active binding for `account_id + device_id`
- set binding status to `Unbound`
- set `unbound_at`
- keep the physical device record unchanged

This supports logout-independent trust removal for one account on a shared device.

### Disable

`disable_device` changes the device status to `Disabled`.

Expected effect:

- the device remains persisted
- heartbeat, bind, and registration-completion flows should reject the device
- historical bindings remain queryable

This is the temporary block path.

### Revoke

`revoke_device` changes the device status to `Revoked`.

Expected effect:

- the device remains persisted for audit and history
- the device is treated as permanently retired
- later host policy may require a full fresh registration instead of reactivation

This is the permanent retirement path.

## Postgres Shape Target

The storage model should include:

- `devices`
- `account_device_bindings`
- `device_nonces`

`devices.account_id` should be removed.

`device_nonces` should move from reserved-table status into an active write path for provisioning and completion flows.

## Decision Summary

This document resolves the earlier ambiguity as follows:

- a device is not the same thing as an account-device relationship
- account-bound direct registration remains supported
- login-free device provisioning is a first-class separate flow
- shared-device support is achieved through bindings, not by rewriting device ownership
- session-to-device linkage is explicitly deferred from this slice
