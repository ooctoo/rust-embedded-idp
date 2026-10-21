import { useCallback, useEffect, useRef, useState } from "react";
import { secureRandomUuid } from "../embedded/browser-session";

type Position = { chain: string; index: number };
const stateKey = "idpConsoleHistory";
function position(): Position | undefined {
  const value = history.state?.[stateKey];
  return value && typeof value.chain === "string" && Number.isSafeInteger(value.index) && value.index >= 0 ? value : undefined;
}
const anchor = (): Position => ({ chain: secureRandomUuid(), index: 0 });
const stamp = (value: Position, url?: string) => history.replaceState({ ...history.state, [stateKey]: value }, "", url);
const urlFor = (hash: string) => `${location.pathname}${location.search}${hash}`;

export function useHashNavigation(canLeave: () => boolean) {
  const [hash, setHash] = useState(() => location.hash);
  const guard = useRef(canLeave);
  guard.current = canLeave;
  const current = useRef({ hash: location.hash, position: position() ?? anchor() });
  const restoring = useRef(false);
  useEffect(() => {
    stamp(current.current.position);
    const changed = () => {
      const nextHash = location.hash, next = position(), previous = current.current;
      if (restoring.current) {
        if (nextHash === previous.hash && next?.chain === previous.position.chain && next.index === previous.position.index) restoring.current = false;
        return;
      }
      // Duplicate hashes still represent distinct history entries. Keep the
      // position current so a later cancelled traversal uses the right distance.
      if (nextHash === previous.hash) {
        const accepted = next ?? anchor();
        stamp(accepted);
        current.current = { hash: nextHash, position: accepted };
        return;
      }
      if (!guard.current()) {
        if (next?.chain === previous.position.chain && next.index !== previous.position.index) {
          restoring.current = true;
          history.go(previous.position.index - next.index);
        } else {
          // Pre-login/external entries have no reliable direction. Preserve the
          // page and draft in place; never guess a traversal that could exit it.
          const accepted = anchor();
          stamp(accepted, urlFor(previous.hash));
          current.current = { hash: previous.hash, position: accepted };
        }
        return;
      }
      // An unknown entry starts a new comparable chain, rather than assigning a
      // guessed index that could make subsequent Back/Forward restoration unsafe.
      const accepted = next && (next.chain !== previous.position.chain || next.index !== previous.position.index) ? next : anchor();
      stamp(accepted);
      current.current = { hash: nextHash, position: accepted };
      setHash(nextHash);
    };
    window.addEventListener("popstate", changed);
    window.addEventListener("hashchange", changed);
    return () => { window.removeEventListener("popstate", changed); window.removeEventListener("hashchange", changed); };
  }, []);
  const navigate = useCallback((next: string, replace = false) => {
    if (restoring.current || next === current.current.hash || !guard.current()) return;
    const accepted = { ...current.current.position, index: current.current.position.index + (replace ? 0 : 1) };
    history[replace ? "replaceState" : "pushState"]({ ...history.state, [stateKey]: accepted }, "", urlFor(next));
    current.current = { hash: next, position: accepted };
    setHash(next);
  }, []);
  return { hash, navigate };
}
