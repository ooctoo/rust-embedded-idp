import assert from "node:assert/strict";

const CONTROL_SELECTOR = 'input:not([type="hidden"]), select, textarea, [role="combobox"]';

/**
 * Assert that the visible controls inside an explicitly supplied Playwright
 * scope have an accessible, non-empty label.  The scope may be a Page or a
 * Locator; callers are responsible for choosing the page region to inspect.
 *
 * Ant Design Select can render a combobox wrapper in addition to its internal
 * input. Both are considered during collection but de-duplicated.
 */
export async function assertControlLabels(scope) {
  assert.ok(scope && typeof scope.locator === "function", "an explicit Playwright Page or Locator scope is required");
  const controls = scope.locator(CONTROL_SELECTOR);
  const stats = await controls.evaluateAll(elements => {
    const visible = element => {
      for (let parent = element; parent; parent = parent.parentElement) {
        if (parent.getAttribute("aria-hidden") === "true") return false;
        const style = getComputedStyle(parent);
        if (style.display === "none" || style.visibility === "hidden") return false;
      }
      return !!element.getClientRects().length;
    };
    const text = node => (node?.getAttribute("aria-label") || node?.textContent || "").trim();
    const labelledBy = element => {
      const ids = (element.getAttribute("aria-labelledby") || "").trim().split(/\s+/).filter(Boolean);
      return ids.length > 0 && ids.every(id => text(document.getElementById(id)) !== "");
    };
    const nativeLabel = element => {
      const labels = element.labels ? [...element.labels] : [];
      const parent = element.closest("label");
      if (parent) labels.push(parent);
      return labels.some(label => text(label) !== "");
    };
    const seen = new Set();
    const visibleControls = elements.filter(element => {
      if (seen.has(element) || !visible(element)) return false;
      seen.add(element);
      return true;
    });
    let native = 0;
    let input = 0;
    let select = 0;
    let textarea = 0;
    let combobox = 0;
    let labelled = 0;
    for (const element of visibleControls) {
      if (element.getAttribute("role") === "combobox") combobox += 1;
      else {
        native += 1;
        if (element.tagName === "INPUT") input += 1;
        else if (element.tagName === "SELECT") select += 1;
        else if (element.tagName === "TEXTAREA") textarea += 1;
      }
      if ((element.getAttribute("aria-label") || "").trim() || labelledBy(element) || nativeLabel(element)) labelled += 1;
    }
    return { total: visibleControls.length, native, input, select, textarea, combobox, labelled, unlabeled: visibleControls.length - labelled };
  });
  assert.equal(stats.unlabeled, 0, `visible controls without an accessible label: ${stats.unlabeled}`);
  return stats;
}
