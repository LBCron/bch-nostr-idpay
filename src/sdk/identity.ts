import {
  CashAddressNetworkPrefix,
  CashAddressType,
  binToHex,
  decodeCashAddress,
  encodeCashAddress,
  generatePrivateKey,
  hash160,
  hash256,
  hexToBin,
  publicKeyToP2pkhCashAddress,
  secp256k1,
  sha256,
  utf8ToBin,
} from '@bitauth/libauth';
import {
  type EventTemplate,
  type VerifiedEvent,
  finalizeEvent,
  generateSecretKey,
  getPublicKey,
  validateEvent,
  verifyEvent,
} from 'nostr-tools/pure';
import * as nip19 from 'nostr-tools/nip19';
import {
  type BchNetworkId,
  NOSTR_BINDING_D_TAG,
  NOSTR_KIND_IDENTITY_BINDING,
  NOSTR_VC_D_TAG_PREFIX,
} from './constants.js';

export interface BchKeyIdentity {
  network: BchNetworkId;
  privateKey?: Uint8Array;
  publicKeyCompressedHex: string;
  pkhHex: string;
  bchAddress: string;
  bchTokenAddress: string;
}

export interface NostrKeyIdentity {
  secretKey?: Uint8Array;
  pubkeyHex: string;
  npub: string;
  nsec?: string;
}

export interface CanonicalBindingPayload {
  version: 'cashlink-did:v1';
  did: string;
  network: BchNetworkId;
  bch_address: string;
  bch_token_address: string;
  bch_pubkey_hex: string;
  bch_pkh_hex: string;
  nostr_pubkey_hex: string;
  nostr_npub: string;
  display_name?: string;
  issued_at: number;
  expires_at: number;
  sequence: number;
  nonce: string;
  prev_rotation_txid: string | null;
  anchor_txid: string | null;
}

export type BchProofScheme = 'bch-compact-msg-v1' | 'bch-schnorr-msg-v1';

export interface BchOwnershipProof {
  scheme: BchProofScheme;
  message_digest_hex: string;
  signature_hex: string;
  signer_pubkey_hex: string;
}

export interface SignedIdentityBinding {
  payload: CanonicalBindingPayload;
  bindingHashHex: string;
  bchProof: BchOwnershipProof;
  nostrEvent: VerifiedEvent;
}

export interface BindingVerificationResult {
  valid: boolean;
  errors: string[];
  did: string | null;
  bchAddress: string | null;
  bchTokenAddress: string | null;
  nostrPubkeyHex: string | null;
  nostrNpub: string | null;
  bindingHashHex: string | null;
}

export interface VerifiableCredentialPayload {
  '@context': ['https://www.w3.org/2018/credentials/v1'];
  id: string;
  type: ['VerifiableCredential', string];
  issuer: {
    did: string;
    nostr_pubkey_hex: string;
    name: string;
  };
  issuanceDate: string;
  expirationDate?: string;
  credentialSubject: {
    id: string;
    bch_token_address: string;
    nostr_npub: string;
    badge: string;
    claims: Record<string, string | number | boolean>;
  };
}

export interface SignedVerifiableCredential {
  credential: VerifiableCredentialPayload;
  nostrEvent: VerifiedEvent;
}

export function getCashAddressPrefix(network: BchNetworkId): CashAddressNetworkPrefix {
  return network === 'mainnet'
    ? CashAddressNetworkPrefix.mainnet
    : CashAddressNetworkPrefix.testnet;
}

/**
 * Generates or derives a non-custodial Bitcoin Cash P2PKH & CashTokens identity.
 */
export function deriveBchIdentityFromPublicKey(
  publicKeyCompressed: Uint8Array,
  network: BchNetworkId = 'mainnet',
  privateKey?: Uint8Array,
): BchKeyIdentity {
  if (publicKeyCompressed.length !== 33) {
    throw new Error(`Expected 33-byte compressed BCH public key, got ${publicKeyCompressed.length}`);
  }
  if (!secp256k1.validatePublicKey(publicKeyCompressed)) {
    throw new Error('Invalid secp256k1 compressed public key');
  }

  const prefix = getCashAddressPrefix(network);
  const stdRes = publicKeyToP2pkhCashAddress({
    publicKey: publicKeyCompressed,
    prefix,
    tokenSupport: false,
  });
  const tokRes = publicKeyToP2pkhCashAddress({
    publicKey: publicKeyCompressed,
    prefix,
    tokenSupport: true,
  });

  if (typeof stdRes === 'string' || typeof tokRes === 'string') {
    throw new Error('Failed to derive CashAddress from public key');
  }

  const pkh = hash160(publicKeyCompressed);
  return {
    network,
    privateKey,
    publicKeyCompressedHex: binToHex(publicKeyCompressed),
    pkhHex: binToHex(pkh),
    bchAddress: stdRes.address,
    bchTokenAddress: tokRes.address,
  };
}

export function createBchKeyIdentity(
  network: BchNetworkId = 'mainnet',
  privateKeyInput?: Uint8Array,
): BchKeyIdentity {
  const privateKey = privateKeyInput ?? generatePrivateKey();
  if (!secp256k1.validatePrivateKey(privateKey)) {
    throw new Error('Invalid secp256k1 BCH private key');
  }
  const pubCompressed = secp256k1.derivePublicKeyCompressed(privateKey);
  if (typeof pubCompressed === 'string') {
    throw new Error(`Failed to derive BCH public key: ${pubCompressed}`);
  }
  return deriveBchIdentityFromPublicKey(pubCompressed, network, privateKey);
}

/**
 * Converts any valid CashAddress (`q...`, `z...`, `p...`, `r...`) to its token-aware (`z...` / `r...`) equivalent.
 */
export function toTokenAwareCashAddress(address: string): string {
  const decoded = decodeCashAddress(address);
  if (typeof decoded === 'string') {
    throw new Error(`Invalid CashAddress "${address}": ${decoded}`);
  }
  const tokenType =
    decoded.type === CashAddressType.p2pkh || decoded.type === CashAddressType.p2pkhWithTokens
      ? CashAddressType.p2pkhWithTokens
      : CashAddressType.p2shWithTokens;

  const encoded = encodeCashAddress({
    prefix: decoded.prefix as CashAddressNetworkPrefix,
    type: tokenType,
    payload: decoded.payload,
  });
  if (typeof encoded === 'string') {
    throw new Error(`Failed to encode token-aware CashAddress: ${encoded}`);
  }
  return encoded.address;
}

/**
 * Generates or derives a non-custodial Nostr identity (`npub1...` + x-only pubkey).
 */
export function createNostrKeyIdentity(secretKeyInput?: Uint8Array): NostrKeyIdentity {
  const secretKey = secretKeyInput ?? generateSecretKey();
  const pubkeyHex = getPublicKey(secretKey);
  const npub = nip19.npubEncode(pubkeyHex);
  const nsec = nip19.nsecEncode(secretKey);
  return {
    secretKey,
    pubkeyHex,
    npub,
    nsec,
  };
}

export function deriveNostrIdentityFromPubkey(pubkeyHexOrNpub: string): NostrKeyIdentity {
  let pubkeyHex = pubkeyHexOrNpub.trim();
  if (pubkeyHex.startsWith('npub1')) {
    const decoded = nip19.decode(pubkeyHex);
    if (decoded.type !== 'npub') {
      throw new Error(`Expected npub1 identifier, got ${decoded.type}`);
    }
    pubkeyHex = decoded.data;
  }
  if (!/^[0-9a-f]{64}$/i.test(pubkeyHex)) {
    throw new Error('Invalid 32-byte hex Nostr public key');
  }
  const normalized = pubkeyHex.toLowerCase();
  return {
    pubkeyHex: normalized,
    npub: nip19.npubEncode(normalized),
  };
}

/**
 * Enforces Paytaca DID Bounty Requirement 1:
 * Strictly forbids reusing the same private key or derived secp256k1 point across BCH and Nostr.
 */
export function assertDistinctKeyMaterial(
  bch: Pick<BchKeyIdentity, 'privateKey' | 'publicKeyCompressedHex'>,
  nostr: Pick<NostrKeyIdentity, 'secretKey' | 'pubkeyHex'>,
): void {
  if (bch.privateKey && nostr.secretKey && binToHex(bch.privateKey) === binToHex(nostr.secretKey)) {
    throw new Error(
      'Key-reuse violation: BCH and Nostr identities MUST NOT share the same private key',
    );
  }
  const bchXOnly = bch.publicKeyCompressedHex.slice(2).toLowerCase();
  if (bchXOnly === nostr.pubkeyHex.toLowerCase()) {
    throw new Error(
      'Key-reuse violation: BCH compressed pubkey x-coordinate matches Nostr BIP-340 pubkey',
    );
  }
}

/**
 * Deterministic canonical JSON serializer with lexicographically sorted keys at every object level.
 */
export function canonicalizeJson(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalizeJson(item)).join(',')}]`;
  }
  const record = value as Record<string, unknown>;
  const sortedKeys = Object.keys(record)
    .filter((k) => record[k] !== undefined)
    .sort();
  const entries = sortedKeys.map((k) => `${JSON.stringify(k)}:${canonicalizeJson(record[k])}`);
  return `{${entries.join(',')}}`;
}

export function formatDidIdentifier(
  network: BchNetworkId,
  bchPkhHex: string,
  nostrPubkeyHex: string,
): string {
  return `did:bchnostr:${network}:${bchPkhHex.toLowerCase()}:${nostrPubkeyHex.slice(0, 16).toLowerCase()}`;
}

export function computeBindingPayloadHash(payload: CanonicalBindingPayload): Uint8Array {
  const canonical = canonicalizeJson(payload);
  return sha256.hash(utf8ToBin(canonical));
}

/**
 * Computes standard Bitcoin Cash Signed Message double-SHA256 digest:
 * hash256("\x18Bitcoin Cash Signed Message:\n" + varint(len) + messageBytes)
 */
export function computeBchSignedMessageDigest(messageUtf8: string): Uint8Array {
  const prefix = utf8ToBin('\x18Bitcoin Cash Signed Message:\n');
  const msgBytes = utf8ToBin(messageUtf8);
  const lenBytes = encodeCompactSizeUint(msgBytes.length);
  const full = new Uint8Array(prefix.length + lenBytes.length + msgBytes.length);
  full.set(prefix, 0);
  full.set(lenBytes, prefix.length);
  full.set(msgBytes, prefix.length + lenBytes.length);
  return hash256(full);
}

function encodeCompactSizeUint(n: number): Uint8Array {
  if (n < 253) {
    return new Uint8Array([n]);
  }
  if (n <= 0xffff) {
    return new Uint8Array([253, n & 0xff, (n >> 8) & 0xff]);
  }
  return new Uint8Array([
    254,
    n & 0xff,
    (n >> 8) & 0xff,
    (n >> 16) & 0xff,
    (n >>> 24) & 0xff,
  ]);
}

export function buildBindingHumanStatement(payload: CanonicalBindingPayload): string {
  const canonical = canonicalizeJson(payload);
  const digestHex = binToHex(sha256.hash(utf8ToBin(canonical)));
  return [
    'CashLink DID — Dual Cryptographic Identity Binding (v1)',
    `DID: ${payload.did}`,
    `BCH Address: ${payload.bch_address}`,
    `CashTokens Address: ${payload.bch_token_address}`,
    `Nostr Pubkey: ${payload.nostr_pubkey_hex}`,
    `Issued At: ${payload.issued_at}`,
    `Expires At: ${payload.expires_at}`,
    `Sequence: ${payload.sequence}`,
    `Nonce: ${payload.nonce}`,
    `Canonical SHA256: ${digestHex}`,
  ].join('\n');
}

export function signBchOwnershipProof(
  payload: CanonicalBindingPayload,
  bchPrivateKey: Uint8Array,
  scheme: BchProofScheme = 'bch-compact-msg-v1',
): BchOwnershipProof {
  const pubCompressed = secp256k1.derivePublicKeyCompressed(bchPrivateKey);
  if (typeof pubCompressed === 'string') {
    throw new Error(`Invalid BCH private key: ${pubCompressed}`);
  }
  const statement = buildBindingHumanStatement(payload);
  const digest = computeBchSignedMessageDigest(statement);

  const sig =
    scheme === 'bch-schnorr-msg-v1'
      ? secp256k1.signMessageHashSchnorr(bchPrivateKey, digest)
      : secp256k1.signMessageHashCompact(bchPrivateKey, digest);

  if (typeof sig === 'string') {
    throw new Error(`BCH signing error: ${sig}`);
  }

  return {
    scheme,
    message_digest_hex: binToHex(digest),
    signature_hex: binToHex(sig),
    signer_pubkey_hex: binToHex(pubCompressed),
  };
}

export interface CreateIdentityBindingOptions {
  bch: BchKeyIdentity;
  nostr: NostrKeyIdentity;
  displayName?: string;
  issuedAt?: number;
  ttlSeconds?: number;
  sequence?: number;
  nonce?: string;
  prevRotationTxid?: string | null;
  anchorTxid?: string | null;
  bchScheme?: BchProofScheme;
  signNostrEvent?: (template: EventTemplate) => Promise<VerifiedEvent>;
  customBchSigner?: (payload: CanonicalBindingPayload) => Promise<BchOwnershipProof>;
}

/**
 * Creates a complete dual-signed BCH × Nostr Identity Binding:
 * 1. Validates non-reuse of private/public keys across BCH and Nostr.
 * 2. Signs the canonical binding statement with the BCH secp256k1 key (Proof A).
 * 3. Signs a NIP-78 `kind: 30078` replaceable attestation event with the Nostr key (Proof B).
 */
export async function createIdentityBinding(
  options: CreateIdentityBindingOptions,
): Promise<SignedIdentityBinding> {
  const { bch, nostr } = options;
  assertDistinctKeyMaterial(bch, nostr);

  const now = options.issuedAt ?? Math.floor(Date.now() / 1000);
  const ttl = options.ttlSeconds ?? 86400 * 180; // 180 days default validity
  const randomNonceBytes = generatePrivateKey().slice(0, 16);
  const nonce = options.nonce ?? binToHex(randomNonceBytes);
  const did = formatDidIdentifier(bch.network, bch.pkhHex, nostr.pubkeyHex);

  const payload: CanonicalBindingPayload = {
    version: 'cashlink-did:v1',
    did,
    network: bch.network,
    bch_address: bch.bchAddress,
    bch_token_address: bch.bchTokenAddress,
    bch_pubkey_hex: bch.publicKeyCompressedHex.toLowerCase(),
    bch_pkh_hex: bch.pkhHex.toLowerCase(),
    nostr_pubkey_hex: nostr.pubkeyHex.toLowerCase(),
    nostr_npub: nostr.npub,
    ...(options.displayName ? { display_name: options.displayName.trim() } : {}),
    issued_at: now,
    expires_at: now + ttl,
    sequence: options.sequence ?? 1,
    nonce,
    prev_rotation_txid: options.prevRotationTxid ?? null,
    anchor_txid: options.anchorTxid ?? null,
  };

  const bindingHashHex = binToHex(computeBindingPayloadHash(payload));

  let bchProof: BchOwnershipProof;
  if (options.customBchSigner) {
    bchProof = await options.customBchSigner(payload);
  } else {
    if (!bch.privateKey) {
      throw new Error('BCH privateKey or customBchSigner required to sign Proof A');
    }
    bchProof = signBchOwnershipProof(payload, bch.privateKey, options.bchScheme);
  }

  const eventContent = JSON.stringify({
    payload,
    binding_hash_hex: bindingHashHex,
    bch_proof: bchProof,
  });

  const tags: string[][] = [
    ['d', NOSTR_BINDING_D_TAG],
    ['did', payload.did],
    ['bch_addr', payload.bch_address],
    ['bch_token_addr', payload.bch_token_address],
    ['bch_pkh', payload.bch_pkh_hex],
    ['binding_hash', bindingHashHex],
    ['i', `bch:${payload.bch_token_address}`, bchProof.signature_hex],
    ['t', 'cashlink-did'],
  ];
  if (payload.anchor_txid) {
    tags.push(['anchor_txid', payload.anchor_txid]);
  }

  const template: EventTemplate = {
    kind: NOSTR_KIND_IDENTITY_BINDING,
    created_at: now,
    tags,
    content: eventContent,
  };

  let nostrEvent: VerifiedEvent;
  if (options.signNostrEvent) {
    nostrEvent = await options.signNostrEvent(template);
  } else {
    if (!nostr.secretKey) {
      throw new Error('Nostr secretKey or signNostrEvent (NIP-07) required to sign Proof B');
    }
    nostrEvent = finalizeEvent(template, nostr.secretKey);
  }

  return {
    payload,
    bindingHashHex,
    bchProof,
    nostrEvent,
  };
}

/**
 * Independently verifies a SignedIdentityBinding (or raw NIP-78 Nostr event) with zero central authority.
 */
export function verifyIdentityBinding(
  input: SignedIdentityBinding | VerifiedEvent,
  options: { nowTimestamp?: number; allowExpired?: boolean } = {},
): BindingVerificationResult {
  const errors: string[] = [];

  let nostrEvent: VerifiedEvent;
  let payload: CanonicalBindingPayload;
  let bchProof: BchOwnershipProof;
  let claimedBindingHashHex: string;

  try {
    if ('nostrEvent' in input) {
      nostrEvent = input.nostrEvent;
      payload = input.payload;
      bchProof = input.bchProof;
      claimedBindingHashHex = input.bindingHashHex;

      // Cross-check that nostrEvent.content actually commits to the exact same payload and proof!
      const parsedContent = JSON.parse(nostrEvent.content) as {
        payload: CanonicalBindingPayload;
        binding_hash_hex: string;
        bch_proof: BchOwnershipProof;
      };
      if (canonicalizeJson(parsedContent.payload) !== canonicalizeJson(payload)) {
        errors.push('Outer binding payload diverges from signed Nostr event content payload');
      }
      if (parsedContent.bch_proof?.signature_hex !== bchProof.signature_hex) {
        errors.push('Outer BCH signature diverges from signed Nostr event content BCH proof');
      }
      if (parsedContent.binding_hash_hex !== claimedBindingHashHex) {
        errors.push('Outer bindingHashHex diverges from signed Nostr event content hash');
      }
    } else {
      nostrEvent = input;
      const parsed = JSON.parse(nostrEvent.content) as {
        payload: CanonicalBindingPayload;
        binding_hash_hex: string;
        bch_proof: BchOwnershipProof;
      };
      payload = parsed.payload;
      bchProof = parsed.bch_proof;
      claimedBindingHashHex = parsed.binding_hash_hex;
    }
  } catch (err) {
    return {
      valid: false,
      errors: [`Malformed identity binding JSON structure: ${(err as Error).message}`],
      did: null,
      bchAddress: null,
      bchTokenAddress: null,
      nostrPubkeyHex: null,
      nostrNpub: null,
      bindingHashHex: null,
    };
  }

  // 1. Verify Nostr Event structure & BIP-340 Schnorr signature (Proof B)
  if (!validateEvent(nostrEvent) || !verifyEvent(nostrEvent)) {
    errors.push('Invalid Nostr BIP-340 Schnorr event signature (Proof B failed)');
  }
  if (nostrEvent.kind !== NOSTR_KIND_IDENTITY_BINDING) {
    errors.push(`Unexpected Nostr event kind: ${nostrEvent.kind} (expected ${NOSTR_KIND_IDENTITY_BINDING})`);
  }
  if (nostrEvent.pubkey.toLowerCase() !== payload.nostr_pubkey_hex?.toLowerCase()) {
    errors.push('Nostr event signer pubkey does not match payload.nostr_pubkey_hex');
  }

  // 2. Verify npub encoding matches nostr_pubkey_hex
  try {
    const expectedNpub = nip19.npubEncode(payload.nostr_pubkey_hex.toLowerCase());
    if (payload.nostr_npub !== expectedNpub) {
      errors.push('payload.nostr_npub does not match payload.nostr_pubkey_hex');
    }
  } catch {
    errors.push('Invalid payload.nostr_pubkey_hex for nip19 encoding');
  }

  // 3. Verify non-reuse of key material across BCH and Nostr
  if (
    typeof payload.bch_pubkey_hex === 'string' &&
    payload.bch_pubkey_hex.length === 66 &&
    payload.bch_pubkey_hex.slice(2).toLowerCase() === payload.nostr_pubkey_hex?.toLowerCase()
  ) {
    errors.push('Key-reuse violation: BCH compressed pubkey x-coordinate equals Nostr pubkey');
  }

  // 4. Verify deterministic binding hash
  const computedBindingHashHex = binToHex(computeBindingPayloadHash(payload));
  if (computedBindingHashHex !== claimedBindingHashHex) {
    errors.push(
      `Binding SHA-256 mismatch: expected ${computedBindingHashHex}, got ${claimedBindingHashHex}`,
    );
  }

  // 5. Verify BCH public key derives the exact claimed bch_address, bch_token_address, and DID
  try {
    const bchPubBin = hexToBin(payload.bch_pubkey_hex);
    const derivedBch = deriveBchIdentityFromPublicKey(bchPubBin, payload.network);
    if (derivedBch.bchAddress !== payload.bch_address) {
      errors.push(
        `Claimed bch_address (${payload.bch_address}) does not match pubkey (${derivedBch.bchAddress})`,
      );
    }
    if (derivedBch.bchTokenAddress !== payload.bch_token_address) {
      errors.push(
        `Claimed bch_token_address (${payload.bch_token_address}) does not match pubkey (${derivedBch.bchTokenAddress})`,
      );
    }
    if (derivedBch.pkhHex !== payload.bch_pkh_hex) {
      errors.push('Claimed bch_pkh_hex does not match hash160(bch_pubkey_hex)');
    }
    const expectedDid = formatDidIdentifier(
      payload.network,
      derivedBch.pkhHex,
      payload.nostr_pubkey_hex,
    );
    if (payload.did !== expectedDid) {
      errors.push(`Malformed DID identifier: expected ${expectedDid}, got ${payload.did}`);
    }
  } catch (err) {
    errors.push(`Invalid BCH public key or CashAddress: ${(err as Error).message}`);
  }

  // 6. Verify BCH secp256k1 cryptographic signature over the human-readable binding statement (Proof A)
  try {
    if (bchProof.signer_pubkey_hex.toLowerCase() !== payload.bch_pubkey_hex.toLowerCase()) {
      errors.push('bchProof.signer_pubkey_hex does not match payload.bch_pubkey_hex');
    }
    const expectedDigest = computeBchSignedMessageDigest(buildBindingHumanStatement(payload));
    const expectedDigestHex = binToHex(expectedDigest);
    if (bchProof.message_digest_hex.toLowerCase() !== expectedDigestHex) {
      errors.push('BCH message digest mismatch (payload was altered after signing)');
    }

    const sigBin = hexToBin(bchProof.signature_hex);
    const pubBin = hexToBin(payload.bch_pubkey_hex);
    const sigValid =
      bchProof.scheme === 'bch-schnorr-msg-v1'
        ? secp256k1.verifySignatureSchnorr(sigBin, pubBin, expectedDigest)
        : secp256k1.verifySignatureCompact(sigBin, pubBin, expectedDigest);

    if (!sigValid) {
      errors.push('Invalid Bitcoin Cash secp256k1 signature (Proof A failed)');
    }
  } catch (err) {
    errors.push(`BCH signature verification exception: ${(err as Error).message}`);
  }

  // 7. Verify timestamp validity window
  const now = options.nowTimestamp ?? Math.floor(Date.now() / 1000);
  if (payload.expires_at <= payload.issued_at) {
    errors.push('Binding expires_at must be strictly greater than issued_at');
  }
  if (!options.allowExpired && now > payload.expires_at) {
    errors.push(`Identity binding expired at ${payload.expires_at} (current: ${now})`);
  }

  return {
    valid: errors.length === 0,
    errors,
    did: payload?.did ?? null,
    bchAddress: payload?.bch_address ?? null,
    bchTokenAddress: payload?.bch_token_address ?? null,
    nostrPubkeyHex: payload?.nostr_pubkey_hex ?? null,
    nostrNpub: payload?.nostr_npub ?? null,
    bindingHashHex: computedBindingHashHex,
  };
}

/**
 * Stretch Goal: Issue & Verify W3C-compatible Verifiable Credentials over Nostr NIP-78 (`kind: 30078`)
 * tied to a verified `did:bchnostr:...` subject.
 */
export function issueVerifiableCredential(params: {
  issuerBinding: SignedIdentityBinding;
  issuerNostrSecretKey: Uint8Array;
  issuerName: string;
  subjectBinding: SignedIdentityBinding;
  credentialType: string;
  badge: string;
  claims: Record<string, string | number | boolean>;
  issuedAt?: number;
}): SignedVerifiableCredential {
  const now = params.issuedAt ?? Math.floor(Date.now() / 1000);
  const issuerCheck = verifyIdentityBinding(params.issuerBinding, { nowTimestamp: now });
  if (!issuerCheck.valid) {
    throw new Error(`Issuer binding invalid: ${issuerCheck.errors.join('; ')}`);
  }
  const subjectCheck = verifyIdentityBinding(params.subjectBinding, { nowTimestamp: now });
  if (!subjectCheck.valid) {
    throw new Error(`Subject binding invalid: ${subjectCheck.errors.join('; ')}`);
  }
  const vcId = `vc:${binToHex(sha256.hash(utf8ToBin(`${params.issuerBinding.payload.did}:${params.subjectBinding.payload.did}:${params.badge}:${now}`))).slice(0, 24)}`;

  const credential: VerifiableCredentialPayload = {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    id: vcId,
    type: ['VerifiableCredential', params.credentialType],
    issuer: {
      did: params.issuerBinding.payload.did,
      nostr_pubkey_hex: params.issuerBinding.payload.nostr_pubkey_hex,
      name: params.issuerName,
    },
    issuanceDate: new Date(now * 1000).toISOString(),
    credentialSubject: {
      id: params.subjectBinding.payload.did,
      bch_token_address: params.subjectBinding.payload.bch_token_address,
      nostr_npub: params.subjectBinding.payload.nostr_npub,
      badge: params.badge,
      claims: params.claims,
    },
  };

  const nostrEvent = finalizeEvent(
    {
      kind: NOSTR_KIND_IDENTITY_BINDING,
      created_at: now,
      tags: [
        ['d', `${NOSTR_VC_D_TAG_PREFIX}${vcId}`],
        ['p', params.subjectBinding.payload.nostr_pubkey_hex],
        ['subject_did', params.subjectBinding.payload.did],
        ['badge', params.badge],
      ],
      content: JSON.stringify(credential),
    },
    params.issuerNostrSecretKey,
  );

  return { credential, nostrEvent };
}

export function verifyVerifiableCredential(vc: SignedVerifiableCredential): {
  valid: boolean;
  errors: string[];
} {
  const errors: string[] = [];
  if (!validateEvent(vc.nostrEvent) || !verifyEvent(vc.nostrEvent)) {
    errors.push('Invalid Nostr signature on Verifiable Credential event');
  }
  if (vc.nostrEvent.pubkey.toLowerCase() !== vc.credential.issuer.nostr_pubkey_hex.toLowerCase()) {
    errors.push('Credential issuer pubkey does not match Nostr event signer');
  }
  try {
    const parsed = JSON.parse(vc.nostrEvent.content) as VerifiableCredentialPayload;
    if (canonicalizeJson(parsed) !== canonicalizeJson(vc.credential)) {
      errors.push('Credential payload does not match signed Nostr event content');
    }
  } catch {
    errors.push('Malformed JSON in Verifiable Credential event content');
  }
  return { valid: errors.length === 0, errors };
}
