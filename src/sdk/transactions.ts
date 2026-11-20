import {
  type LibauthOutput as CashScriptLibauthOutput,
  type NetworkProvider,
  SignatureTemplate,
  TransactionBuilder,
  type Utxo,
  type WcTransactionObject,
  placeholderP2PKHUnlocker,
} from 'cashscript';
import {
  type Output as LibauthOutput,
  binToHex,
  cashAddressToLockingBytecode,
  createVirtualMachineBch2025,
  decodeTransactionBCH,
  hashTransactionUiOrder,
  hexToBin,
  utf8ToBin,
  verifyTransactionTokens,
} from '@bitauth/libauth';
import {
  BLAZE_ANCHOR_PREFIX_HEX,
  BLAZE_PAY_PREFIX_HEX,
  BLAZE_REVOKE_PREFIX_HEX,
  DUST_SATOSHIS,
  PUSD_CATEGORY_ID,
  PUSD_DECIMALS,
  TOKEN_DUST_SATOSHIS,
} from './constants.js';
import { type SignedIdentityBinding, verifyIdentityBinding } from './identity.js';

export interface DecodedBlazeCommitment {
  type: 'anchor' | 'revoke' | 'payment';
  prefixHex: string;
  hashOrMemoHex: string;
  vout: number;
}

export interface BuiltTransactionResult {
  signedHex?: string;
  txid?: string;
  wcTransaction: WcTransactionObject;
  inputPaths: [number, string, number][];
  feeSatoshis: bigint;
  sourceOutputs: LibauthOutput[];
}

/**
 * Parses a human-readable ParyonUSD string (e.g. "25.50" or "10") into exact integer base units
 * using official BCMR `decimals: 2` (`1.00 PUSD = 100n`).
 */
export function parsePusdAmount(humanAmount: string): bigint {
  const trimmed = humanAmount.trim();
  if (!/^\d+(\.\d{1,2})?$/.test(trimmed)) {
    throw new Error(
      `Invalid PUSD amount "${humanAmount}": expected positive number with up to ${PUSD_DECIMALS} decimal places`,
    );
  }
  const [wholePart, fracPart = ''] = trimmed.split('.');
  const paddedFrac = fracPart.padEnd(PUSD_DECIMALS, '0');
  const total = BigInt(wholePart) * 100n + BigInt(paddedFrac);
  if (total <= 0n) {
    throw new Error('PUSD amount must be strictly greater than 0.00');
  }
  return total;
}

export function formatPusdAmount(baseUnits: bigint): string {
  const negative = baseUnits < 0n;
  const abs = negative ? -baseUnits : baseUnits;
  const whole = abs / 100n;
  const frac = (abs % 100n).toString().padStart(PUSD_DECIMALS, '0');
  return `${negative ? '-' : ''}${whole.toString()}.${frac}`;
}

export function parseBchAmountToSatoshis(humanBch: string): bigint {
  const trimmed = humanBch.trim();
  if (!/^\d+(\.\d{1,8})?$/.test(trimmed)) {
    throw new Error(`Invalid BCH amount "${humanBch}": expected up to 8 decimal places`);
  }
  const [wholePart, fracPart = ''] = trimmed.split('.');
  const paddedFrac = fracPart.padEnd(8, '0');
  const sats = BigInt(wholePart) * 100_000_000n + BigInt(paddedFrac);
  if (sats < DUST_SATOSHIS) {
    throw new Error(`BCH payment must be at least ${DUST_SATOSHIS} satoshis (dust threshold)`);
  }
  return sats;
}

/**
 * Encodes an on-chain CashLink DID Anchor OP_RETURN locking bytecode:
 * `0x6a 0x04 "BLZI" 0x20 <32-byte sha256(canonical_binding_payload)>`
 */
export function encodeBlazeAnchorOpReturn(bindingHashHex: string): Uint8Array {
  if (!/^[0-9a-f]{64}$/i.test(bindingHashHex)) {
    throw new Error(`Expected 32-byte hex binding hash, got "${bindingHashHex}"`);
  }
  return hexToBin(`6a04${BLAZE_ANCHOR_PREFIX_HEX}20${bindingHashHex.toLowerCase()}`);
}

/**
 * Decodes `"BLZI"` (anchor), `"BLZR"` (revocation), or `"BLZP"` (payment memo) OP_RETURN outputs.
 */
export function decodeBlazeOpReturn(
  lockingBytecodeInput: Uint8Array | string,
  vout = 0,
): DecodedBlazeCommitment | null {
  const hex =
    typeof lockingBytecodeInput === 'string'
      ? lockingBytecodeInput.toLowerCase().replace(/^0x/, '')
      : binToHex(lockingBytecodeInput).toLowerCase();

  // Standard 4-byte push after OP_RETURN (0x6a 0x04 <4-byte prefix>)
  if (!hex.startsWith('6a04') || hex.length < 16) {
    return null;
  }
  const prefixHex = hex.slice(4, 12);
  let type: DecodedBlazeCommitment['type'] | null = null;
  if (prefixHex === BLAZE_ANCHOR_PREFIX_HEX) type = 'anchor';
  else if (prefixHex === BLAZE_REVOKE_PREFIX_HEX) type = 'revoke';
  else if (prefixHex === BLAZE_PAY_PREFIX_HEX) type = 'payment';
  if (!type) return null;

  // Next push opcode length byte
  const pushLen = parseInt(hex.slice(12, 14), 16);
  if (!Number.isFinite(pushLen) || hex.length < 14 + pushLen * 2) {
    return null;
  }
  const hashOrMemoHex = hex.slice(14, 14 + pushLen * 2);
  return {
    type,
    prefixHex,
    hashOrMemoHex,
    vout,
  };
}

function computeTxidHex(txBin: Uint8Array): string {
  const hash = hashTransactionUiOrder(txBin) as Uint8Array | string;
  return typeof hash === 'string' ? hash : binToHex(hash);
}

export function extractBlazeCommitmentsFromTxHex(txHex: string): {
  txid: string;
  commitments: DecodedBlazeCommitment[];
} {
  const txBin = hexToBin(txHex.trim());
  const decoded = decodeTransactionBCH(txBin);
  if (typeof decoded === 'string') {
    throw new Error(`Invalid raw BCH transaction hex: ${decoded}`);
  }
  const txid = computeTxidHex(txBin);
  const commitments: DecodedBlazeCommitment[] = [];
  decoded.outputs.forEach((out, idx) => {
    const parsed = decodeBlazeOpReturn(out.lockingBytecode, idx);
    if (parsed) commitments.push(parsed);
  });
  return { txid, commitments };
}

function utxoToLibauthOutput(utxo: Utxo, fallbackAddress: string): LibauthOutput {
  let lockingBytecode: Uint8Array;
  if (utxo.lockingBytecode) {
    lockingBytecode = hexToBin(utxo.lockingBytecode.replace(/^0x/, ''));
  } else {
    const res = cashAddressToLockingBytecode(fallbackAddress);
    if (typeof res === 'string') {
      throw new Error(`Invalid CashAddress ${fallbackAddress}: ${res}`);
    }
    lockingBytecode = res.bytecode;
  }
  return {
    lockingBytecode,
    valueSatoshis: utxo.satoshis,
    ...(utxo.token
      ? {
          token: {
            amount: utxo.token.amount,
            category: hexToBin(utxo.token.category),
            ...(utxo.token.nft
              ? {
                  nft: {
                    capability: utxo.token.nft.capability,
                    commitment: hexToBin(utxo.token.nft.commitment),
                  },
                }
              : {}),
          },
        }
      : {}),
  };
}

/**
 * Builds an on-chain CashLink DID Identity Anchor transaction (`OP_RETURN "BLZI" + sha256(payload)`),
 * optionally minting a genesis mutable CashTokens Identity NFT into `IdentityAnchor.cash` when a
 * `vout === 0` funding UTXO is available.
 */
export function buildIdentityAnchorTx(params: {
  provider: NetworkProvider;
  senderAddress: string;
  utxos: Utxo[];
  bindingHashHex: string;
  privateKey?: Uint8Array;
  feeRate?: number;
  mintIdentityNft?: {
    covenantTokenAddress: string;
    commitmentHex: string;
  };
}): BuiltTransactionResult {
  if (!/^[0-9a-f]{64}$/i.test(params.bindingHashHex)) {
    throw new Error('bindingHashHex must be 64 hex characters (32 bytes)');
  }

  const pureBchUtxos = params.utxos.filter((u) => !u.token);
  if (pureBchUtxos.length === 0) {
    throw new Error('No spendable BCH UTXOs available to fund Identity Anchor transaction');
  }

  // Sort so a vout === 0 UTXO comes first when minting a CashTokens genesis Identity NFT
  const sortedUtxos = [...pureBchUtxos].sort((a, b) => {
    if (params.mintIdentityNft) {
      if (a.vout === 0 && b.vout !== 0) return -1;
      if (b.vout === 0 && a.vout !== 0) return 1;
    }
    return Number(b.satoshis - a.satoshis);
  });

  if (params.mintIdentityNft && sortedUtxos[0].vout !== 0) {
    throw new Error(
      'Minting a genesis CashTokens Identity NFT requires at least one BCH UTXO with vout === 0',
    );
  }

  // Gather enough UTXOs to cover dust + fees (~2500 sats)
  const selected: Utxo[] = [];
  let totalIn = 0n;
  for (const u of sortedUtxos) {
    selected.push(u);
    totalIn += u.satoshis;
    if (totalIn >= 3500n) break;
  }
  if (totalIn < 1500n) {
    throw new Error(`Insufficient BCH balance (${totalIn} sats) for Identity Anchor transaction`);
  }

  const lockingRes = cashAddressToLockingBytecode(params.senderAddress);
  if (typeof lockingRes === 'string') {
    throw new Error(`Invalid sender CashAddress: ${lockingRes}`);
  }
  const senderLockingHex = binToHex(lockingRes.bytecode);
  const spendable = selected.map((u) => ({
    ...u,
    lockingBytecode: u.lockingBytecode ?? senderLockingHex,
  }));

  const configureOutputs = (tb: TransactionBuilder) => {
    if (params.mintIdentityNft) {
      const genesisCategory = spendable[0].txid;
      tb.addOutput({
        to: params.mintIdentityNft.covenantTokenAddress,
        amount: TOKEN_DUST_SATOSHIS,
        token: {
          category: genesisCategory,
          amount: 0n,
          nft: {
            capability: 'mutable',
            commitment: params.mintIdentityNft.commitmentHex,
          },
        },
      });
    }
    tb.addOpReturnOutput([
      `0x${BLAZE_ANCHOR_PREFIX_HEX}`,
      `0x${params.bindingHashHex.toLowerCase()}`,
    ]);
    tb.addBchChangeOutputIfNeeded({
      to: params.senderAddress,
      feeRate: params.feeRate ?? 1.1,
    });
  };

  // Always build the WalletConnect/WizardConnect transaction object with placeholder unlockers
  const wcBuilder = new TransactionBuilder({ provider: params.provider });
  const placeholder = placeholderP2PKHUnlocker(params.senderAddress);
  wcBuilder.addInputs(spendable, placeholder);
  configureOutputs(wcBuilder);
  const wcTransaction = wcBuilder.generateWcTransactionObject({
    broadcast: false,
    userPrompt: 'CashLink DID: Anchor BCH × Nostr Identity On-Chain',
  });
  const { feeSats } = wcBuilder.calculateTransactionFee();

  let signedHex: string | undefined;
  let txid: string | undefined;
  if (params.privateKey) {
    const sigBuilder = new TransactionBuilder({ provider: params.provider });
    const sigTemplate = new SignatureTemplate(params.privateKey);
    sigBuilder.addInputs(spendable, sigTemplate.unlockP2PKH());
    configureOutputs(sigBuilder);
    signedHex = sigBuilder.build();
    txid = computeTxidHex(hexToBin(signedHex));
  }

  const sourceOutputs = spendable.map((u) => utxoToLibauthOutput(u, params.senderAddress));
  const inputPaths: [number, string, number][] = spendable.map((_, idx) => [idx, 'receive', 0]);

  return {
    signedHex,
    txid,
    wcTransaction,
    inputPaths,
    feeSatoshis: feeSats,
    sourceOutputs,
  };
}

/**
 * Builds a real BCH or ParyonUSD (`PUSD`) CashToken payment transaction addressed to a
 * cryptographically verified CashLink DID (`SignedIdentityBinding`).
 */
export function buildIdentityPaymentTx(params: {
  provider: NetworkProvider;
  senderAddress: string;
  senderTokenAddress: string;
  recipientBinding: SignedIdentityBinding;
  asset: 'BCH' | 'PUSD';
  amountBaseUnits: bigint;
  utxos: Utxo[];
  memo?: string;
  privateKey?: Uint8Array;
  feeRate?: number;
  nowTimestamp?: number;
}): BuiltTransactionResult {
  // Mandatory cryptographic verification of recipient's dual BCH×Nostr proof BEFORE sending funds!
  const verification = verifyIdentityBinding(params.recipientBinding, {
    nowTimestamp: params.nowTimestamp,
  });
  if (!verification.valid || !verification.bchTokenAddress || !verification.bchAddress) {
    throw new Error(
      `Refusing payment to unverified identity: ${verification.errors.join('; ')}`,
    );
  }

  if (params.amountBaseUnits <= 0n) {
    throw new Error('Payment amount must be strictly positive');
  }

  const lockingRes = cashAddressToLockingBytecode(params.senderAddress);
  if (typeof lockingRes === 'string') {
    throw new Error(`Invalid sender CashAddress: ${lockingRes}`);
  }
  const senderLockingHex = binToHex(lockingRes.bytecode);

  const selected: Utxo[] = [];
  if (params.asset === 'PUSD') {
    const pusdUtxos = params.utxos.filter(
      (u) => u.token?.category.toLowerCase() === PUSD_CATEGORY_ID && u.token.amount > 0n,
    );
    let gatheredTokens = 0n;
    for (const u of pusdUtxos) {
      selected.push(u);
      gatheredTokens += u.token!.amount;
      if (gatheredTokens >= params.amountBaseUnits) break;
    }
    if (gatheredTokens < params.amountBaseUnits) {
      throw new Error(
        `Insufficient ParyonUSD (PUSD) balance: have ${formatPusdAmount(gatheredTokens)} PUSD, need ${formatPusdAmount(params.amountBaseUnits)} PUSD`,
      );
    }

    // Add pure BCH UTXOs to cover token output dust + network fees
    const pureBch = params.utxos.filter((u) => !u.token);
    let bchSum = selected.reduce((acc, u) => acc + u.satoshis, 0n);
    for (const u of pureBch) {
      if (bchSum >= TOKEN_DUST_SATOSHIS * 2n + 2000n) break;
      selected.push(u);
      bchSum += u.satoshis;
    }
    if (bchSum < TOKEN_DUST_SATOSHIS + 500n) {
      throw new Error(`Insufficient BCH satoshis (${bchSum}) to cover CashTokens dust and miner fee`);
    }
  } else {
    if (params.amountBaseUnits < DUST_SATOSHIS) {
      throw new Error(`BCH payment must be >= ${DUST_SATOSHIS} satoshis`);
    }
    const pureBch = params.utxos.filter((u) => !u.token);
    let bchSum = 0n;
    for (const u of pureBch) {
      selected.push(u);
      bchSum += u.satoshis;
      if (bchSum >= params.amountBaseUnits + 1500n) break;
    }
    if (bchSum < params.amountBaseUnits + 300n) {
      throw new Error(
        `Insufficient BCH balance: have ${bchSum} sats, need at least ${params.amountBaseUnits + 300n} sats`,
      );
    }
  }

  const spendable = selected.map((u) => ({
    ...u,
    lockingBytecode: u.lockingBytecode ?? senderLockingHex,
  }));

  const configureOutputs = (tb: TransactionBuilder) => {
    if (params.asset === 'PUSD') {
      tb.addOutput({
        to: verification.bchTokenAddress!,
        amount: TOKEN_DUST_SATOSHIS,
        token: {
          category: PUSD_CATEGORY_ID,
          amount: params.amountBaseUnits,
        },
      });
      tb.addTokenChangeOutputIfNeeded({
        category: PUSD_CATEGORY_ID,
        to: params.senderTokenAddress,
      });
    } else {
      tb.addOutput({
        to: verification.bchAddress!,
        amount: params.amountBaseUnits,
      });
    }

    if (params.memo && params.memo.trim().length > 0) {
      const memoHex = binToHex(utf8ToBin(params.memo.trim().slice(0, 64)));
      tb.addOpReturnOutput([`0x${BLAZE_PAY_PREFIX_HEX}`, `0x${memoHex}`]);
    }

    tb.addBchChangeOutputIfNeeded({
      to: params.senderAddress,
      feeRate: params.feeRate ?? 1.1,
    });
  };

  const wcBuilder = new TransactionBuilder({ provider: params.provider });
  wcBuilder.addInputs(spendable, placeholderP2PKHUnlocker(params.senderAddress));
  configureOutputs(wcBuilder);
  const promptAsset =
    params.asset === 'PUSD'
      ? `${formatPusdAmount(params.amountBaseUnits)} PUSD`
      : `${params.amountBaseUnits} sats BCH`;
  const wcTransaction = wcBuilder.generateWcTransactionObject({
    broadcast: false,
    userPrompt: `CashLink DID: Pay ${promptAsset} to ${verification.nostrNpub?.slice(0, 16)}…`,
  });
  const { feeSats } = wcBuilder.calculateTransactionFee();

  let signedHex: string | undefined;
  let txid: string | undefined;
  if (params.privateKey) {
    const sigBuilder = new TransactionBuilder({ provider: params.provider });
    const sigTemplate = new SignatureTemplate(params.privateKey);
    sigBuilder.addInputs(spendable, sigTemplate.unlockP2PKH());
    configureOutputs(sigBuilder);
    signedHex = sigBuilder.build();
    txid = computeTxidHex(hexToBin(signedHex));
  }

  const sourceOutputs = spendable.map((u) => utxoToLibauthOutput(u, params.senderAddress));
  const inputPaths: [number, string, number][] = spendable.map((_, idx) => [idx, 'receive', 0]);

  return {
    signedHex,
    txid,
    wcTransaction,
    inputPaths,
    feeSatoshis: feeSats,
    sourceOutputs,
  };
}

/**
 * Evaluates a signed Bitcoin Cash transaction (including CashTokens PUSD / mutable NFT rules
 * and every input's unlocking + locking bytecode) directly inside `@bitauth/libauth`'s
 * consensus BCH 2025 Virtual Machine.
 */
export function verifySignedBchTransactionVm(
  signedTxHex: string,
  sourceOutputs: (LibauthOutput | CashScriptLibauthOutput)[],
): { valid: boolean; txid: string | null; error?: string } {
  const txBin = hexToBin(signedTxHex.trim());
  const decoded = decodeTransactionBCH(txBin);
  if (typeof decoded === 'string') {
    return { valid: false, txid: null, error: `Transaction decode error: ${decoded}` };
  }

  const normalizedSources: LibauthOutput[] = sourceOutputs.map((so) => ({
    lockingBytecode: so.lockingBytecode,
    valueSatoshis: so.valueSatoshis,
    ...(so.token
      ? {
          token: {
            amount: so.token.amount,
            category: so.token.category,
            ...(so.token.nft
              ? {
                  nft: {
                    capability: so.token.nft.capability,
                    commitment: so.token.nft.commitment,
                  },
                }
              : {}),
          },
        }
      : {}),
  }));

  const tokenResult = verifyTransactionTokens(decoded, normalizedSources, {
    maximumTokenCommitmentLength: 40,
  });
  if (tokenResult !== true) {
    return { valid: false, txid: null, error: `CashTokens validation failed: ${tokenResult}` };
  }

  const vm = createVirtualMachineBch2025();
  const vmResult = vm.verify({
    transaction: decoded,
    sourceOutputs: normalizedSources,
  });
  if (vmResult !== true) {
    return { valid: false, txid: null, error: `BCH VM script evaluation failed: ${vmResult}` };
  }

  return {
    valid: true,
    txid: computeTxidHex(txBin),
  };
}
