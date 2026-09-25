import "@ant-design/v5-patch-for-react-19";
import "./admin.css";

export { PermissionDirectory, type PermissionDirectoryClient, type PermissionDirectoryProps } from "../management/permission-directory";
export { ManagementClient, ManagementError, type AdminPage, type AuthState,
  type DirectoryPermission, type PermissionDirectoryFilter, type PermissionKey } from "../management/client";
