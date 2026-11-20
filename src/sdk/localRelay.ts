import { type AddressInfo, type WebSocket, WebSocketServer } from 'ws';
import { type VerifiedEvent, validateEvent, verifyEvent } from 'nostr-tools/pure';
import type { Filter } from 'nostr-tools/filter';

interface ClientSubscription {
  ws: WebSocket;
  subId: string;
  filters: Filter[];
}

export interface EmbeddedNostrRelay {
  url: string;
  port: number;
  storedEventCount: () => number;
  close: () => Promise<void>;
}

/**
 * Lightweight embedded NIP-01 + NIP-33/NIP-78 (parameterized replaceable) + NIP-59 (gift wrap)
 * WebSocket Nostr Relay built on `ws`.
 *
 * Used for 100% deterministic, zero-mock E2E protocol verification of:
 *   1. `nostr-tools` `SimplePool` `kind: 30078` Identity Binding publish & discovery
 *   2. `@wizardconnect/core` + `@wizardconnect/dapp` + `@wizardconnect/wallet` NIP-59 gift-wrapped
 *      `wiz://` BIP32 `xpub` handshake and real BCH transaction signing!
 */
export async function startEmbeddedNostrRelay(port = 0): Promise<EmbeddedNostrRelay> {
  const wss = new WebSocketServer({ host: '127.0.0.1', port });

  await new Promise<void>((resolve, reject) => {
    wss.once('listening', () => resolve());
    wss.once('error', (err) => reject(err));
  });

  const addr = wss.address() as AddressInfo;
  const url = `ws://127.0.0.1:${addr.port}`;

  const eventsById = new Map<string, VerifiedEvent>();
  const subscriptions = new Map<string, ClientSubscription>();

  const matchesFilter = (event: VerifiedEvent, filter: Filter): boolean => {
    if (filter.ids && !filter.ids.includes(event.id)) return false;
    if (filter.authors && !filter.authors.includes(event.pubkey)) return false;
    if (filter.kinds && !filter.kinds.includes(event.kind)) return false;
    if (filter.since !== undefined && event.created_at < filter.since) return false;
    if (filter.until !== undefined && event.created_at > filter.until) return false;

    for (const [key, expectedValues] of Object.entries(filter)) {
      if (key.startsWith('#') && Array.isArray(expectedValues)) {
        const tagName = key.slice(1);
        const eventTagValues = event.tags
          .filter((t) => t[0] === tagName && typeof t[1] === 'string')
          .map((t) => t[1]);
        const hasIntersection = expectedValues.some((v) => eventTagValues.includes(String(v)));
        if (!hasIntersection) return false;
      }
    }
    return true;
  };

  const matchesAnyFilter = (event: VerifiedEvent, filters: Filter[]): boolean =>
    filters.some((f) => matchesFilter(event, f));

  wss.on('connection', (ws) => {
    const connId = Math.random().toString(36).slice(2);

    ws.on('message', (raw) => {
      let msg: unknown;
      try {
        msg = JSON.parse(raw.toString());
      } catch {
        ws.send(JSON.stringify(['NOTICE', 'Invalid JSON frame']));
        return;
      }
      if (!Array.isArray(msg) || typeof msg[0] !== 'string') return;

      const verb = msg[0];
      if (verb === 'EVENT') {
        const rawEv = msg[1] as { id?: string } | undefined;
        const ev = msg[1] as VerifiedEvent;
        if (!validateEvent(ev) || !verifyEvent(ev)) {
          ws.send(
            JSON.stringify(['OK', rawEv?.id ?? '', false, 'invalid: signature check failed']),
          );
          return;
        }

        // Ephemeral events (20000 <= kind < 30000) are broadcast to active subs without storage
        const isEphemeral = ev.kind >= 20000 && ev.kind < 30000;
        if (!isEphemeral) {
          // NIP-33 / NIP-78 Parameterized Replaceable Events (30000 <= kind < 40000)
          if (ev.kind >= 30000 && ev.kind < 40000) {
            const dTag = ev.tags.find((t) => t[0] === 'd')?.[1] ?? '';
            for (const [existingId, existingEv] of eventsById.entries()) {
              const existingD = existingEv.tags.find((t) => t[0] === 'd')?.[1] ?? '';
              if (
                existingEv.kind === ev.kind &&
                existingEv.pubkey === ev.pubkey &&
                existingD === dTag
              ) {
                if (ev.created_at >= existingEv.created_at) {
                  eventsById.delete(existingId);
                } else {
                  ws.send(JSON.stringify(['OK', ev.id, true, 'duplicate: older replaceable event']));
                  return;
                }
              }
            }
          }
          eventsById.set(ev.id, ev);
        }

        ws.send(JSON.stringify(['OK', ev.id, true, '']));

        // Fan-out to all matching live subscriptions
        for (const sub of subscriptions.values()) {
          if (sub.ws.readyState === sub.ws.OPEN && matchesAnyFilter(ev, sub.filters)) {
            sub.ws.send(JSON.stringify(['EVENT', sub.subId, ev]));
          }
        }
      } else if (verb === 'REQ') {
        const subId = String(msg[1] ?? '');
        const rawFilters = msg.slice(2);
        // Handle both standard NIP-01 `["REQ", subId, filter1, filter2]` and array-wrapped filters
        const filters: Filter[] = (
          Array.isArray(rawFilters[0]) ? rawFilters[0] : rawFilters
        ).filter((f): f is Filter => typeof f === 'object' && f !== null);

        subscriptions.set(`${connId}:${subId}`, { ws, subId, filters });

        let matching = [...eventsById.values()].filter((ev) => matchesAnyFilter(ev, filters));
        matching.sort((a, b) => b.created_at - a.created_at);

        const maxLimit = filters.reduce(
          (acc, f) => (typeof f.limit === 'number' ? Math.max(acc, f.limit) : acc),
          0,
        );
        if (maxLimit > 0) {
          matching = matching.slice(0, maxLimit);
        }

        for (const ev of matching) {
          if (ws.readyState === ws.OPEN) {
            ws.send(JSON.stringify(['EVENT', subId, ev]));
          }
        }
        if (ws.readyState === ws.OPEN) {
          ws.send(JSON.stringify(['EOSE', subId]));
        }
      } else if (verb === 'CLOSE') {
        const subId = String(msg[1] ?? '');
        subscriptions.delete(`${connId}:${subId}`);
      }
    });

    ws.on('close', () => {
      for (const key of [...subscriptions.keys()]) {
        if (key.startsWith(`${connId}:`)) {
          subscriptions.delete(key);
        }
      }
    });
  });

  return {
    url,
    port: addr.port,
    storedEventCount: () => eventsById.size,
    close: () =>
      new Promise<void>((resolve) => {
        for (const client of wss.clients) {
          client.terminate();
        }
        wss.close(() => resolve());
      }),
  };
}
