import { useId, type CSSProperties } from "react";
import { validScanCode, validateScanSourceUri, type ScanTarget } from "./scan-login-protocol";
import styles from "./device-scan-login.module.css";

export type ScanSourceEntryProps = {
  target: Pick<ScanTarget, "verification_uri">;
  displayCode?: string;
  language?: "zh-CN" | "en-US";
  className?: string;
  style?: CSSProperties;
};

function sourceUrl(uri: string, displayCode?: string): string | undefined {
  try {
    const canonical = validateScanSourceUri(uri);
    if (displayCode === undefined) return canonical;
    if (!validScanCode(displayCode, "create")) return undefined;
    const url = new URL(canonical, typeof location === "undefined" ? "https://localhost" : location.origin);
    url.hash = `code=${encodeURIComponent(displayCode)}`;
    return url.href;
  } catch { return undefined; }
}

/** Opens the configured source-device approval H5; it does not approve on the embed's behalf. */
export function ScanSourceEntry({ target, displayCode, language = "zh-CN", className, style }: ScanSourceEntryProps) {
  const id = useId();
  const href = sourceUrl(target.verification_uri, displayCode);
  const zh = language === "zh-CN";
  return <section className={`${styles.root} ${className ?? ""}`} style={style} aria-labelledby={id}>
    <h2 id={id}>{zh ? "在手机上确认登录" : "Confirm sign-in on your phone"}</h2>
    <p>{zh ? "打开此身份入口的扫码页面，在手机上核对并明确批准这台设备。扫码或认领短码本身不会批准登录。" : "Open the scan page for this identity entry, review the device, and explicitly approve on your phone. Scanning or claiming a code does not approve the sign-in."}</p>
    {href ? <a className={styles.button} href={href} rel="noreferrer">{zh ? "打开手机确认页面" : "Open phone confirmation"}</a> : <p className={styles.alert} role="status">{zh ? "宿主扫码确认地址或短码无效；请检查接入配置。" : "The host scan confirmation URL or code is invalid. Check the host configuration."}</p>}
  </section>;
}
