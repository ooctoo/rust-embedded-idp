import { QRCode } from "antd";
import JsBarcode from "jsbarcode";
import { createRoot, type Root } from "react-dom/client";

type Kind = "qr" | "barcode";

function Code({ value, kind }: { value: string; kind: Kind }) {
  if (kind === "qr") return <QRCode value={value} type="svg" size={220} errorLevel="M" />;
  return <svg ref={(node) => { if (node) JsBarcode(node, value, { format: "CODE128", displayValue: true, height: 72, margin: 8 }); }} />;
}

const roots = new WeakMap<Element, Root>();

function render(element: Element, value: string, kind: Kind) {
  if (!value || value.length > 256 || !/^[\x20-\x7e]+$/.test(value)) throw new Error("scan code must be printable ASCII");
  let root = roots.get(element);
  if (!root) {
    root = createRoot(element);
    roots.set(element, root);
  }
  root.render(<Code value={value} kind={kind} />);
}

declare global { interface Window { EmbeddedIdpScanCode?: { render: typeof render }; } }
window.EmbeddedIdpScanCode = { render };
