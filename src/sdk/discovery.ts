import { ElectrumNetworkProvider, Network, type Utxo } from 'cashscript';
import { SimplePool } from 'nostr-tools/pool';
import type { Filter } from 'nostr-tools/filter';
import type { VerifiedEvent } from 'nostr-tools/pure';
import {
  type BchNetworkId,
  DEFAULT_NOSTR_DISCOVERY_RELAYS,
  NOSTR_BINDING_D_TAG,
  NOSTR_KIND_IDENTITY_BINDING,
} from './constants.js';
import {
  type BchOwnershipProof,
  type CanonicalBindingPayload,
  type SignedIdentityBinding,
  deriveNostrIdentityFromPubkey,
  toTokenAwareCashAddress,
  verifyIdentityBinding,
} from './identity.js';

export interface PublishBindingResult {
  publishedRelays: string[];
  failedRelays: { relay: string; error: string }[];
}

export interface DiscoveredIdentity {
  binding: SignedIdentityBinding;
  relaySeenAt: number;
}

/**
 * Publishes a dual-signed `SignedIdentityBinding` (`kind: 30078`) across decentralized Nostr relays.
 */
export async function publishIdentityBinding(
  binding: SignedIdentityBinding,
  relayUrls: string[] = DEFAULT_NOSTR_DISCOVERY_RELAYS,
  poolInstance?: SimplePool,
): Promise<PublishBindingResult> {
  const verification = verifyIdentityBinding(binding);
  if (!verification.valid) {
    throw new Error(`Cannot publish invalid identity binding: ${verification.errors.join('; ')}`);
  }

  const pool = poolInstance ?? new SimplePool();
  const shouldClose = !poolInstance;
  const publishedRelays: string[] = [];
  const failedRelays: { relay: string; error: string }[] = [];

  try {
    const publishPromises = pool.publish(relayUrls, binding.nostrEvent);
    const settled = await Promise.allSettled(publishPromises);
    settled.forEach((res, idx) => {
      const relay = relayUrls[idx] ?? 'unknown';
      if (res.status === 'fulfilled') {
        publishedRelays.push(relay);
      } else {
        failedRelays.push({
          relay,
          error: res.reason instanceof Error ? res.reason.message : String(res.reason),
        });
      }
    });
  } finally {
    if (shouldClose) {
      pool.close(relayUrls);
    }
  }

  return { publishedRelays, failedRelays };
}

function parseVerifiedBindingFromEvent(event: VerifiedEvent): SignedIdentityBinding | null {
  const check = verifyIdentityBinding(event);
  if (!check.valid) return null;
  try {
    const parsed = JSON.parse(event.content) as {
      payload: CanonicalBindingPayload;
      binding_hash_hex: string;
      bch_proof: BchOwnershipProof;
    };
    return {
      payload: parsed.payload,
      bindingHashHex: parsed.binding_hash_hex,
      bchProof: parsed.bch_proof,
      nostrEvent: event,
    };
  } catch {
    return null;
  }
}

function pickLatestValidBinding(events: VerifiedEvent[]): SignedIdentityBinding | null {
  const validBindings: SignedIdentityBinding[] = [];
  for (const ev of events) {
    const parsed = parseVerifiedBindingFromEvent(ev);
    if (parsed) validBindings.push(parsed);
  }
  if (validBindings.length === 0) return null;

  // Prefer highest sequence number, then newest issued_at / created_at
  validBindings.sort((a, b) => {
    if (b.payload.sequence !== a.payload.sequence) {
      return b.payload.sequence - a.payload.sequence;
    }
    if (b.payload.issued_at !== a.payload.issued_at) {
      return b.payload.issued_at - a.payload.issued_at;
    }
    return b.nostrEvent.created_at - a.nostrEvent.created_at;
  });
  return validBindings[0];
}

/**
 * Queries decentralized Nostr relays for a verified CashLink DID binding by Nostr `npub1...`
 * or 64-char hex pubkey. Automatically rejects any tampered or invalid events!
 */
export async function resolveIdentityByNostr(
  npubOrHex: string,
  relayUrls: string[] = DEFAULT_NOSTR_DISCOVERY_RELAYS,
  options: { maxWaitMs?: number; pool?: SimplePool } = {},
): Promise<SignedIdentityBinding | null> {
  const { pubkeyHex } = deriveNostrIdentityFromPubkey(npubOrHex);
  const pool = options.pool ?? new SimplePool();
  const shouldClose = !options.pool;

  const filter: Filter = {
    kinds: [NOSTR_KIND_IDENTITY_BINDING],
    authors: [pubkeyHex],
    '#d': [NOSTR_BINDING_D_TAG],
    limit: 10,
  };

  try {
    const events = (await pool.querySync(relayUrls, filter, {
      maxWait: options.maxWaitMs ?? 3500,
    })) as VerifiedEvent[];
    return pickLatestValidBinding(events);
  } finally {
    if (shouldClose) {
      pool.close(relayUrls);
    }
  }
}

/**
 * Reverse-resolves a Bitcoin Cash address (`bitcoincash:q...` or `bitcoincash:z...`) to its
 * cryptographically verified Nostr identity across decentralized Nostr relays.
 */
export async function resolveIdentityByBchAddress(
  bchAddressInput: string,
  relayUrls: string[] = DEFAULT_NOSTR_DISCOVERY_RELAYS,
  options: { maxWaitMs?: number; pool?: SimplePool } = {},
): Promise<SignedIdentityBinding | null> {
  const tokenAddr = toTokenAwareCashAddress(bchAddressInput.trim());
  const pool = options.pool ?? new SimplePool();
  const shouldClose = !options.pool;

  const filter: Filter = {
    kinds: [NOSTR_KIND_IDENTITY_BINDING],
    '#bch_token_addr': [tokenAddr],
    limit: 10,
  };

  try {
    const events = (await pool.querySync(relayUrls, filter, {
      maxWait: options.maxWaitMs ?? 3500,
    })) as VerifiedEvent[];
    return pickLatestValidBinding(events);
  } finally {
    if (shouldClose) {
      pool.close(relayUrls);
    }
  }
}

/**
 * Creates a live CashScript `ElectrumNetworkProvider` connected to Bitcoin Cash Mainnet or Chipnet.
 */
export function createElectrumProvider(network: BchNetworkId = 'mainnet'): ElectrumNetworkProvider {
  const target = network === 'mainnet' ? Network.MAINNET : Network.CHIPNET;
  return new ElectrumNetworkProvider(target);
}

export async function fetchAddressUtxosLive(
  address: string,
  network: BchNetworkId = 'mainnet',
): Promise<Utxo[]> {
  const provider = createElectrumProvider(network);
  return provider.getUtxos(address);
}

export async function broadcastSignedTransactionLive(
  signedTxHex: string,
  network: BchNetworkId = 'mainnet',
): Promise<string> {
  const provider = createElectrumProvider(network);
  return provider.sendRawTransaction(signedTxHex);
}
