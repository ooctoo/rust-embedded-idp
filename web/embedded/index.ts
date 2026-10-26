export { EmbeddedAuth, type EmbeddedAuthProps } from "./auth";
export { EmbeddedIdentityClient, IdentityError, type IdentityTransport, type LoginCapabilities,
  type IdentitySession, type IdentitySnapshot, type JoinedTenant, type JoinedTenantPage, type MyRole, type MyRolePage } from "./client";

export { secureRandomUuid, validateBrowserClientConfig, type BrowserClientConfig } from "./browser-session";

export { EmbeddedDeviceClient, type SubjectDevice, type DevicePage, type DeviceKeyMetadata, type UnbindIntent, type DeviceOperationReceipt } from "./device-client";
export { DeviceSelfService, type DeviceSelfServiceProps } from "./device-self-service";

export { DeviceRegistrationClient, RegistrationError, buildDeviceRegistrationProofBytes,
  type DeviceRegistrationTarget, type DeviceRegistrationPhase, type DeviceRegistrationPublicJwk,
  type DeviceRegistrationRecord, type DeviceRegistrationContext, type DeviceRegistrationSigner,
  type DeviceRegistrationAdmission, type DeviceRegistrationStore, type DeviceRegistrationSnapshot,
  type DeviceRegistrationClientOptions } from "./device-registration-client";
export { DeviceRegistration, type DeviceRegistrationProps } from "./device-registration";

export { DeviceKeyRotationClient, DeviceKeyRotationError, buildDeviceKeyRotationProofBytes,
  type DeviceKeyRotationTarget, type DeviceKeyRotationOwner, type DeviceKeyRotationPublicJwk,
  type DeviceKeyRotationRecord, type DeviceKeyRotationContext, type DeviceKeyRotationSigner,
  type DeviceKeyRotationStore, type DeviceKeyRotationPhase, type DeviceKeyRotationSnapshot,
  type DeviceKeyRotationClientOptions } from "./device-key-rotation-client";
export { DeviceKeyRotation, type DeviceKeyRotationProps } from "./device-key-rotation";

export { DeviceScanClient, DeviceScanError, type DeviceScanRecord, type DeviceScanPhase,
  type DeviceScanSnapshot, type DeviceScanStore, type DeviceScanSessions, type DeviceScanClientOptions } from "./device-scan-client";
export { buildDeviceScanProofBytes, type ScanTarget, type ScanProgress, type ScanBundle, type ScanSigner, type ScanSignInput } from "./scan-login-protocol";
export { DeviceScanLogin, type DeviceScanLoginProps, type ScanCodeRenderer } from "./device-scan-login";
export { ScanSourceEntry, type ScanSourceEntryProps } from "./scan-source-entry";
