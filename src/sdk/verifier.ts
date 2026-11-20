import {
  binToHex,
  generatePrivateKey,
  hexToBin,
  secp256k1,
} from '@bitauth/libauth';
import {
  type EventTemplate,
  type VerifiedEvent,
  finalizeEvent,
  validateEvent,
  verifyEvent,
} from 'nostr-tools/pure';
import { NOSTR_KIND_AUTH_CHALLENGE } from './constants.js';
import {
  type SignedIdentityBinding,
  computeBchSignedMessageDigest,
  verifyIdentityBinding,
} from './identity.js';

export interface AuthChallenge {
  challengeHex: string;
  domain: string;
  relayUrl: string;
  issuedAt: number;
  expiresAt: number;
}

export interface AuthChallengeResponse {
  challenge: AuthChallenge;
  binding: SignedIdentityBinding;
  authEvent: VerifiedEvent;
  bchChallengeSignatureHex?: string;
}

export interface AuthVerificationReport {
  authenticated: boolean;
  dualFactorBchConfirmed: boolean;
  did: string | null;
  bchAddress: string | null;
  bchTokenAddress: string | null;
  nostrNpub: string | null;
  errors: string[];
}

/**
 * Generates a fresh 32-byte cryptographic challenge for "Login with BCH×Nostr"
 * relying-party authentication (Requirement 4).
 */
export function createAuthChallenge(params: {
  domain: string;
  relayUrl?: string;
  issuedAt?: number;
  ttlSeconds?: number;
}): AuthChallenge {
  const challengeBytes = generatePrivateKey(); // 32 CSPRNG bytes
  const issuedAt = params.issuedAt ?? Math.floor(Date.now() / 1000);
  const ttl = params.ttlSeconds ?? 300; // 5 minutes default
  return {
    challengeHex: binToHex(challengeBytes),
    domain: params.domain.trim().toLowerCase(),
    relayUrl: params.relayUrl ?? 'wss://relay.riften.net:443',
    issuedAt,
    expiresAt: issuedAt + ttl,
  };
}

export function formatBchChallengeMessage(challenge: AuthChallenge, did: string): string {
  return [
    'CashLink DID — Challenge-Response Login',
    `Domain: ${challenge.domain}`,
    `DID: ${did}`,
    `Challenge: ${challenge.challengeHex}`,
    `Issued At: ${challenge.issuedAt}`,
    `Expires At: ${challenge.expiresAt}`,
  ].join('\n');
}

/**
 * Signs a NIP-42 (`kind: 22242`) ephemeral authentication event proving live control of the
 * Nostr keypair, optionally accompanied by a live BCH secp256k1 challenge signature for
 * hardware-grade dual-key interactive login.
 */
export async function respondToAuthChallenge(params: {
  challenge: AuthChallenge;
  binding: SignedIdentityBinding;
  nostrSecretKey?: Uint8Array;
  signNostrEvent?: (template: EventTemplate) => Promise<VerifiedEvent>;
  bchPrivateKey?: Uint8Array;
  nowTimestamp?: number;
}): Promise<AuthChallengeResponse> {
  const now = params.nowTimestamp ?? Math.floor(Date.now() / 1000);

  let bchChallengeSignatureHex: string | undefined;
  if (params.bchPrivateKey) {
    const msg = formatBchChallengeMessage(params.challenge, params.binding.payload.did);
    const digest = computeBchSignedMessageDigest(msg);
    const sig = secp256k1.signMessageHashCompact(params.bchPrivateKey, digest);
    if (typeof sig === 'string') {
      throw new Error(`Failed to sign BCH challenge: ${sig}`);
    }
    bchChallengeSignatureHex = binToHex(sig);
  }

  const tags: string[][] = [
    ['challenge', params.challenge.challengeHex],
    ['domain', params.challenge.domain],
    ['relay', params.challenge.relayUrl],
    ['did', params.binding.payload.did],
    ['binding_hash', params.binding.bindingHashHex],
  ];
  if (bchChallengeSignatureHex) {
    tags.push(['bch_challenge_sig', bchChallengeSignatureHex]);
  }

  const template: EventTemplate = {
    kind: NOSTR_KIND_AUTH_CHALLENGE,
    created_at: now,
    tags,
    content: `Authenticate ${params.binding.payload.did} on ${params.challenge.domain}`,
  };

  let authEvent: VerifiedEvent;
  if (params.signNostrEvent) {
    authEvent = await params.signNostrEvent(template);
  } else {
    if (!params.nostrSecretKey) {
      throw new Error('Either nostrSecretKey or signNostrEvent is required');
    }
    authEvent = finalizeEvent(template, params.nostrSecretKey);
  }

  return {
    challenge: params.challenge,
    binding: params.binding,
    authEvent,
    bchChallengeSignatureHex,
  };
}

/**
 * Relying-party standalone verifier:
 * Verifies challenge freshness, domain binding, NIP-42 `kind: 22242` Schnorr signature,
 * full dual BCH×Nostr `SignedIdentityBinding`, and optional live BCH second-factor signature.
 */
export function verifyAuthChallengeResponse(
  response: AuthChallengeResponse,
  expectedChallenge: AuthChallenge,
  options: { nowTimestamp?: number; requireLiveBchSignature?: boolean } = {},
): AuthVerificationReport {
  const errors: string[] = [];
  const now = options.nowTimestamp ?? Math.floor(Date.now() / 1000);

  // 1. Verify underlying dual BCH×Nostr identity binding
  const bindingCheck = verifyIdentityBinding(response.binding, { nowTimestamp: now });
  if (!bindingCheck.valid) {
    errors.push(...bindingCheck.errors.map((e) => `Binding error: ${e}`));
  }

  // 2. Verify challenge integrity & expiration
  if (response.challenge.challengeHex !== expectedChallenge.challengeHex) {
    errors.push('Challenge nonce mismatch');
  }
  if (response.challenge.domain !== expectedChallenge.domain) {
    errors.push(
      `Relying-party domain mismatch: expected "${expectedChallenge.domain}", got "${response.challenge.domain}"`,
    );
  }
  if (now > expectedChallenge.expiresAt) {
    errors.push(`Authentication challenge expired at ${expectedChallenge.expiresAt}`);
  }
  if (now < expectedChallenge.issuedAt - 60) {
    errors.push('Authentication challenge issued in the future');
  }

  // 3. Verify NIP-42 (`kind: 22242`) ephemeral auth event signature & tags
  const { authEvent } = response;
  if (!validateEvent(authEvent) || !verifyEvent(authEvent)) {
    errors.push('Invalid BIP-340 Schnorr signature on kind:22242 auth event');
  }
  if (authEvent.kind !== NOSTR_KIND_AUTH_CHALLENGE) {
    errors.push(`Unexpected auth event kind: ${authEvent.kind} (expected ${NOSTR_KIND_AUTH_CHALLENGE})`);
  }
  if (authEvent.pubkey.toLowerCase() !== response.binding.payload.nostr_pubkey_hex.toLowerCase()) {
    errors.push('Auth event signer pubkey does not match bound Nostr identity');
  }

  const getTag = (name: string) => authEvent.tags.find((t) => t[0] === name)?.[1];
  if (getTag('challenge') !== expectedChallenge.challengeHex) {
    errors.push('Auth event missing matching ["challenge", ...] tag');
  }
  if (getTag('domain') !== expectedChallenge.domain) {
    errors.push('Auth event missing matching ["domain", ...] tag');
  }
  if (getTag('did') !== response.binding.payload.did) {
    errors.push('Auth event ["did", ...] tag does not match bound DID');
  }
  if (getTag('binding_hash') !== response.binding.bindingHashHex) {
    errors.push('Auth event ["binding_hash", ...] tag does not match binding SHA-256');
  }

  // 4. Verify optional (or required) live BCH secp256k1 challenge signature
  let dualFactorBchConfirmed = false;
  const bchSigHex = response.bchChallengeSignatureHex ?? getTag('bch_challenge_sig');
  if (bchSigHex) {
    try {
      const msg = formatBchChallengeMessage(expectedChallenge, response.binding.payload.did);
      const digest = computeBchSignedMessageDigest(msg);
      const sigBin = hexToBin(bchSigHex);
      const pubBin = hexToBin(response.binding.payload.bch_pubkey_hex);
      if (secp256k1.verifySignatureCompact(sigBin, pubBin, digest)) {
        dualFactorBchConfirmed = true;
      } else {
        errors.push('Invalid live BCH secp256k1 challenge signature');
      }
    } catch (err) {
      errors.push(`Live BCH challenge signature malformed: ${(err as Error).message}`);
    }
  } else if (options.requireLiveBchSignature) {
    errors.push('Live BCH secp256k1 challenge signature required by relying party');
  }

  return {
    authenticated: errors.length === 0,
    dualFactorBchConfirmed,
    did: bindingCheck.did,
    bchAddress: bindingCheck.bchAddress,
    bchTokenAddress: bindingCheck.bchTokenAddress,
    nostrNpub: bindingCheck.nostrNpub,
    errors,
  };
}
