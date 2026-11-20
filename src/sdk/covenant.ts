import {
  type Artifact,
  Contract,
  type NetworkProvider,
  SignatureTemplate,
  type SpendableUtxo,
  TransactionBuilder,
  type TransactionDetails,
} from 'cashscript';
import {
  binToHex,
  cashAddressToLockingBytecode,
  decodeTransactionBCH,
  hexToBin,
  sha256,
} from '@bitauth/libauth';
import identityAnchorArtifactJson from '../contracts/IdentityAnchor.artifact.json' with { type: 'json' };
import { BLAZE_REVOKE_PREFIX_HEX, TOKEN_DUST_SATOSHIS } from './constants.js';

export const IDENTITY_ANCHOR_ARTIFACT = identityAnchorArtifactJson as unknown as Artifact;

export interface DecodedIdentityNftCommitment {
  bindingHashHex: string;
  sequence: bigint;
}

/**
 * Encodes a 40-byte CashTokens mutable NFT commitment for `IdentityAnchor.cash`:
 *   bytes[0..32]  = sha256(nostrPubkey32 || ownerPkh20)
 *   bytes[32..40] = sequence encoded as 8-byte little-endian signed integer (`OP_NUM2BIN 8`)
 */
export function encodeIdentityNftCommitment(params: {
  nostrPubkeyHex: string;
  ownerPkhHex: string;
  sequence: bigint | number;
}): string {
  if (!/^[0-9a-f]{64}$/i.test(params.nostrPubkeyHex)) {
    throw new Error('nostrPubkeyHex must be 32-byte hex (64 chars)');
  }
  if (!/^[0-9a-f]{40}$/i.test(params.ownerPkhHex)) {
    throw new Error('ownerPkhHex must be 20-byte hex (40 chars)');
  }
  const seq = BigInt(params.sequence);
  if (seq < 0n || seq > 0x7fff_ffff_ffff_ffffn) {
    throw new Error('sequence must be a non-negative 63-bit integer');
  }

  const nostrBytes = hexToBin(params.nostrPubkeyHex);
  const pkhBytes = hexToBin(params.ownerPkhHex);
  const preimage = new Uint8Array(52);
  preimage.set(nostrBytes, 0);
  preimage.set(pkhBytes, 32);

  const bindingHash = sha256.hash(preimage);
  const seqBytes = encodeVmInt64LE(seq);

  const full = new Uint8Array(40);
  full.set(bindingHash, 0);
  full.set(seqBytes, 32);
  return binToHex(full);
}

export function decodeIdentityNftCommitment(commitmentHex: string): DecodedIdentityNftCommitment {
  const clean = commitmentHex.replace(/^0x/, '').toLowerCase();
  if (clean.length !== 80) {
    throw new Error(`Expected 40-byte (80 hex chars) Identity NFT commitment, got ${clean.length / 2} bytes`);
  }
  const bindingHashHex = clean.slice(0, 64);
  const seqBytes = hexToBin(clean.slice(64, 80));
  const sequence = decodeVmInt64LE(seqBytes);
  return { bindingHashHex, sequence };
}

function encodeVmInt64LE(value: bigint): Uint8Array {
  const out = new Uint8Array(8);
  let rem = value;
  for (let i = 0; i < 8; i++) {
    out[i] = Number(rem & 0xffn);
    rem >>= 8n;
  }
  return out;
}

function decodeVmInt64LE(bytes: Uint8Array): bigint {
  let result = 0n;
  for (let i = 7; i >= 0; i--) {
    const b = i === 7 ? bytes[i] & 0x7f : bytes[i];
    result = (result << 8n) | BigInt(b);
  }
  if ((bytes[7] & 0x80) !== 0) {
    result = -result;
  }
  return result;
}

async function broadcastBuiltTransaction(
  builder: TransactionBuilder,
  provider: NetworkProvider,
): Promise<TransactionDetails> {
  const hex = builder.build();
  const txid = await provider.sendRawTransaction(hex);
  const decoded = decodeTransactionBCH(hexToBin(hex));
  if (typeof decoded === 'string') {
    throw new Error(`Failed to decode broadcasted transaction: ${decoded}`);
  }
  return {
    ...decoded,
    txid,
    hex,
  };
}

/**
 * Instantiates the compiled `IdentityAnchor.cash` CashScript `0.14.0` covenant for a given
 * 20-byte guardian PKH (`hash160(guardianPubkey)`).
 */
export function instantiateIdentityAnchor(
  guardianPkhHex: string,
  provider: NetworkProvider,
) {
  if (!/^[0-9a-f]{40}$/i.test(guardianPkhHex)) {
    throw new Error('guardianPkhHex must be 20-byte hex (40 chars)');
  }
  return new Contract(IDENTITY_ANCHOR_ARTIFACT, [guardianPkhHex.toLowerCase()], {
    provider,
    contractType: 'p2sh32',
  });
}

/**
 * Executes an authorized `rotateIdentity` transition on the `IdentityAnchor` covenant,
 * rotating the Nostr pubkey and/or BCH owner keypair while incrementing the on-chain
 * NFT sequence counter by +1.
 */
export async function executeRotateIdentity(params: {
  contract: ReturnType<typeof instantiateIdentityAnchor>;
  anchorUtxo: SpendableUtxo;
  feeUtxo: SpendableUtxo;
  feePayerPrivateKey: Uint8Array;
  feeChangeAddress: string;
  currentOwnerPublicKeyHex: string;
  currentOwnerPrivateKey: Uint8Array;
  currentNostrPubkeyHex: string;
  nextNostrPubkeyHex: string;
  nextOwnerPkhHex: string;
}): Promise<{ txDetails: TransactionDetails; nextCommitmentHex: string; nextSequence: bigint }> {
  if (!params.anchorUtxo.token?.nft || params.anchorUtxo.token.nft.capability !== 'mutable') {
    throw new Error('anchorUtxo must carry a mutable CashTokens Identity NFT');
  }
  const prevDecoded = decodeIdentityNftCommitment(params.anchorUtxo.token.nft.commitment);
  const nextSequence = prevDecoded.sequence + 1n;
  const nextCommitmentHex = encodeIdentityNftCommitment({
    nostrPubkeyHex: params.nextNostrPubkeyHex,
    ownerPkhHex: params.nextOwnerPkhHex,
    sequence: nextSequence,
  });

  const ownerSigTemplate = new SignatureTemplate(params.currentOwnerPrivateKey);
  const feeSigTemplate = new SignatureTemplate(params.feePayerPrivateKey);

  const builder = new TransactionBuilder({ provider: params.contract.provider });
  builder
    .addInput(
      params.anchorUtxo,
      params.contract.unlock.rotateIdentity(
        params.currentOwnerPublicKeyHex,
        ownerSigTemplate,
        params.currentNostrPubkeyHex,
        params.nextNostrPubkeyHex,
        params.nextOwnerPkhHex,
      ),
    )
    .addInput(params.feeUtxo, feeSigTemplate.unlockP2PKH())
    .addOutput({
      to: params.contract.tokenAddress,
      amount: TOKEN_DUST_SATOSHIS,
      token: {
        category: params.anchorUtxo.token.category,
        amount: 0n,
        nft: {
          capability: 'mutable',
          commitment: nextCommitmentHex,
        },
      },
    })
    .addBchChangeOutputIfNeeded({
      to: params.feeChangeAddress,
      feeRate: 1.1,
    });

  const txDetails = await broadcastBuiltTransaction(builder, params.contract.provider);
  return { txDetails, nextCommitmentHex, nextSequence };
}

/**
 * Executes guardian social/hardware recovery (`recoverIdentity`) on the `IdentityAnchor` covenant.
 */
export async function executeGuardianRecovery(params: {
  contract: ReturnType<typeof instantiateIdentityAnchor>;
  anchorUtxo: SpendableUtxo;
  feeUtxo: SpendableUtxo;
  feePayerPrivateKey: Uint8Array;
  feeChangeAddress: string;
  guardianPublicKeyHex: string;
  guardianPrivateKey: Uint8Array;
  recoveredNostrPubkeyHex: string;
  recoveredOwnerPkhHex: string;
}): Promise<{ txDetails: TransactionDetails; nextCommitmentHex: string; nextSequence: bigint }> {
  if (!params.anchorUtxo.token?.nft || params.anchorUtxo.token.nft.capability !== 'mutable') {
    throw new Error('anchorUtxo must carry a mutable CashTokens Identity NFT');
  }
  const prevDecoded = decodeIdentityNftCommitment(params.anchorUtxo.token.nft.commitment);
  const nextSequence = prevDecoded.sequence + 1n;
  const nextCommitmentHex = encodeIdentityNftCommitment({
    nostrPubkeyHex: params.recoveredNostrPubkeyHex,
    ownerPkhHex: params.recoveredOwnerPkhHex,
    sequence: nextSequence,
  });

  const guardianSig = new SignatureTemplate(params.guardianPrivateKey);
  const feeSig = new SignatureTemplate(params.feePayerPrivateKey);

  const builder = new TransactionBuilder({ provider: params.contract.provider });
  builder
    .addInput(
      params.anchorUtxo,
      params.contract.unlock.recoverIdentity(
        params.guardianPublicKeyHex,
        guardianSig,
        params.recoveredNostrPubkeyHex,
        params.recoveredOwnerPkhHex,
      ),
    )
    .addInput(params.feeUtxo, feeSig.unlockP2PKH())
    .addOutput({
      to: params.contract.tokenAddress,
      amount: TOKEN_DUST_SATOSHIS,
      token: {
        category: params.anchorUtxo.token.category,
        amount: 0n,
        nft: {
          capability: 'mutable',
          commitment: nextCommitmentHex,
        },
      },
    })
    .addBchChangeOutputIfNeeded({
      to: params.feeChangeAddress,
      feeRate: 1.1,
    });

  const txDetails = await broadcastBuiltTransaction(builder, params.contract.provider);
  return { txDetails, nextCommitmentHex, nextSequence };
}

/**
 * Executes permanent self-sovereign identity revocation (`revokeIdentity`), burning the mutable
 * Identity NFT and recording an immutable `"BLZR"` OP_RETURN revocation marker on-chain.
 */
export async function executeRevokeIdentity(params: {
  contract: ReturnType<typeof instantiateIdentityAnchor>;
  anchorUtxo: SpendableUtxo;
  feeUtxo: SpendableUtxo;
  feePayerPrivateKey: Uint8Array;
  feeChangeAddress: string;
  currentOwnerPublicKeyHex: string;
  currentOwnerPrivateKey: Uint8Array;
  currentNostrPubkeyHex: string;
}): Promise<TransactionDetails> {
  if (!params.anchorUtxo.token?.nft) {
    throw new Error('anchorUtxo must carry an Identity NFT');
  }
  const prevDecoded = decodeIdentityNftCommitment(params.anchorUtxo.token.nft.commitment);
  const ownerSig = new SignatureTemplate(params.currentOwnerPrivateKey);
  const feeSig = new SignatureTemplate(params.feePayerPrivateKey);

  const builder = new TransactionBuilder({ provider: params.contract.provider });
  builder
    .addInput(
      params.anchorUtxo,
      params.contract.unlock.revokeIdentity(
        params.currentOwnerPublicKeyHex,
        ownerSig,
        params.currentNostrPubkeyHex,
      ),
    )
    .addInput(params.feeUtxo, feeSig.unlockP2PKH())
    .addOpReturnOutput([`0x${BLAZE_REVOKE_PREFIX_HEX}`, `0x${prevDecoded.bindingHashHex}`])
    .addBchChangeOutputIfNeeded({
      to: params.feeChangeAddress,
      feeRate: 1.1,
    });

  return broadcastBuiltTransaction(builder, params.contract.provider);
}

export function addressToLockingBytecodeHex(address: string): string {
  const res = cashAddressToLockingBytecode(address);
  if (typeof res === 'string') {
    throw new Error(`Invalid CashAddress "${address}": ${res}`);
  }
  return binToHex(res.bytecode);
}
