import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { MockNetworkProvider, Network, randomUtxo } from 'cashscript';
import { generatePrivateKey } from '@bitauth/libauth';
import {
  BLAZE_ANCHOR_PREFIX_HEX,
  BLAZE_REVOKE_PREFIX_HEX,
  DerivationPath,
  NonCustodialBip32WizardWalletAdapter,
  PUSD_CATEGORY_ID,
  TOKEN_DUST_SATOSHIS,
  WalletConnectionManager,
  addressToLockingBytecodeHex,
  buildIdentityAnchorTx,
  buildIdentityPaymentTx,
  createAuthChallenge,
  createBchKeyIdentity,
  createIdentityBinding,
  createNostrKeyIdentity,
  createProgrammaticWizardDapp,
  decodeBlazeOpReturn,
  decodeIdentityNftCommitment,
  deriveBchIdentityFromWizardManager,
  encodeIdentityNftCommitment,
  executeGuardianRecovery,
  executeRevokeIdentity,
  executeRotateIdentity,
  extractBlazeCommitmentsFromTxHex,
  formatPusdAmount,
  instantiateIdentityAnchor,
  issueVerifiableCredential,
  parsePusdAmount,
  publishIdentityBinding,
  requestWizardConnectSignature,
  resolveIdentityByBchAddress,
  resolveIdentityByNostr,
  respondToAuthChallenge,
  verifyAuthChallengeResponse,
  verifyIdentityBinding,
  verifySignedBchTransactionVm,
  verifyVerifiableCredential,
} from '../src/sdk/index.js';
import { type EmbeddedNostrRelay, startEmbeddedNostrRelay } from '../src/sdk/localRelay.js';

describe('CashLink DID — End-to-End Cryptographic, CashScript Covenant, PUSD & WizardConnect Suite', () => {
  let relay: EmbeddedNostrRelay;

  beforeAll(async () => {
    relay = await startEmbeddedNostrRelay(0);
  });

  afterAll(async () => {
    if (relay) {
      await relay.close();
    }
  });

  it('1. enforces non-custodial key separation and dual BCH × Nostr cryptographic binding + tamper rejection', async () => {
    const aliceBch = createBchKeyIdentity('mainnet');
    const aliceNostr = createNostrKeyIdentity();

    expect(aliceBch.bchAddress.startsWith('bitcoincash:q')).toBe(true);
    expect(aliceBch.bchTokenAddress.startsWith('bitcoincash:z')).toBe(true);
    expect(aliceNostr.npub.startsWith('npub1')).toBe(true);

    // Reject reusing the exact same 32-byte private key across BCH and Nostr
    const sharedSecret = generatePrivateKey();
    const reusedBch = createBchKeyIdentity('mainnet', sharedSecret);
    const reusedNostr = createNostrKeyIdentity(sharedSecret);
    await expect(
      createIdentityBinding({ bch: reusedBch, nostr: reusedNostr }),
    ).rejects.toThrow(/Key-reuse violation/);

    // Valid dual binding (Compact ECDSA Proof A + NIP-78 kind:30078 Proof B)
    const binding = await createIdentityBinding({
      bch: aliceBch,
      nostr: aliceNostr,
      displayName: 'Alice Nakamoto',
      issuedAt: 1_794_175_000,
      ttlSeconds: 86_400,
    });

    const verified = verifyIdentityBinding(binding, { nowTimestamp: 1_794_176_000 });
    expect(verified.valid).toBe(true);
    expect(verified.errors).toEqual([]);
    expect(verified.bchTokenAddress).toBe(aliceBch.bchTokenAddress);
    expect(verified.nostrNpub).toBe(aliceNostr.npub);

    // Also verify Schnorr Proof A variant
    const schnorrBinding = await createIdentityBinding({
      bch: aliceBch,
      nostr: aliceNostr,
      bchScheme: 'bch-schnorr-msg-v1',
      issuedAt: 1_794_175_000,
    });
    expect(verifyIdentityBinding(schnorrBinding, { nowTimestamp: 1_794_175_100 }).valid).toBe(true);

    // Tamper 1: attacker swaps payout CashTokens address to steal PUSD
    const attackerBch = createBchKeyIdentity('mainnet');
    const tamperedAddressBinding = structuredClone(binding);
    tamperedAddressBinding.payload.bch_token_address = attackerBch.bchTokenAddress;
    const tamperedCheck = verifyIdentityBinding(tamperedAddressBinding, {
      nowTimestamp: 1_794_176_000,
    });
    expect(tamperedCheck.valid).toBe(false);
    expect(tamperedCheck.errors.length).toBeGreaterThan(0);

    // Tamper 2: expired binding rejected
    const expiredCheck = verifyIdentityBinding(binding, {
      nowTimestamp: 1_794_175_000 + 90_000,
    });
    expect(expiredCheck.valid).toBe(false);
    expect(expiredCheck.errors.some((e) => e.includes('expired'))).toBe(true);

    // Stretch Goal: Portable Verifiable Credential ("Verified BCH Merchant")
    const issuerBch = createBchKeyIdentity('mainnet');
    const issuerNostr = createNostrKeyIdentity();
    const issuerBinding = await createIdentityBinding({
      bch: issuerBch,
      nostr: issuerNostr,
      displayName: 'Paytaca Merchant Guild',
      issuedAt: 1_794_175_500,
    });
    const vc = issueVerifiableCredential({
      issuerBinding,
      issuerNostrSecretKey: issuerNostr.secretKey!,
      issuerName: 'Paytaca Merchant Guild',
      subjectBinding: binding,
      credentialType: 'BchMerchantCredential',
      badge: 'Verified PUSD Merchant',
      claims: { acceptedAsset: 'PUSD', tier: 'Mainnet' },
      issuedAt: 1_794_176_000,
    });
    expect(verifyVerifiableCredential(vc).valid).toBe(true);
  });

  it('2. verifies interactive "Login with BCH×Nostr" NIP-42 (kind:22242) challenge-response and blocks phishing/replay', async () => {
    const bch = createBchKeyIdentity('mainnet');
    const nostr = createNostrKeyIdentity();
    const binding = await createIdentityBinding({ bch, nostr, issuedAt: 1_794_175_000 });

    const challenge = createAuthChallenge({
      domain: 'cashlink.bchblaze.cash',
      relayUrl: relay.url,
      issuedAt: 1_794_175_100,
      ttlSeconds: 300,
    });

    const authResponse = await respondToAuthChallenge({
      challenge,
      binding,
      nostrSecretKey: nostr.secretKey,
      bchPrivateKey: bch.privateKey,
      nowTimestamp: 1_794_175_120,
    });

    const report = verifyAuthChallengeResponse(authResponse, challenge, {
      nowTimestamp: 1_794_175_150,
      requireLiveBchSignature: true,
    });
    expect(report.authenticated).toBe(true);
    expect(report.dualFactorBchConfirmed).toBe(true);
    expect(report.did).toBe(binding.payload.did);

    // Phishing domain mismatch must fail
    const phishingChallenge = { ...challenge, domain: 'evil-phish.example' };
    const phishingReport = verifyAuthChallengeResponse(authResponse, phishingChallenge, {
      nowTimestamp: 1_794_175_150,
    });
    expect(phishingReport.authenticated).toBe(false);
    expect(phishingReport.errors.some((e) => e.includes('domain mismatch'))).toBe(true);

    // Expired challenge must fail
    const expiredReport = verifyAuthChallengeResponse(authResponse, challenge, {
      nowTimestamp: 1_794_176_000,
    });
    expect(expiredReport.authenticated).toBe(false);
  });

  it('3. constructs consensus-valid BCH "BLZI" OP_RETURN anchor & ParyonUSD (PUSD) CashToken payments verified in libauth VM', async () => {
    expect(parsePusdAmount('25.50')).toBe(2550n);
    expect(formatPusdAmount(2550n)).toBe('25.50');

    const provider = new MockNetworkProvider();
    const senderBch = createBchKeyIdentity('chipnet');
    const senderNostr = createNostrKeyIdentity();
    const senderBinding = await createIdentityBinding({
      bch: senderBch,
      nostr: senderNostr,
      issuedAt: 1_794_175_000,
    });

    const recipientBch = createBchKeyIdentity('chipnet');
    const recipientNostr = createNostrKeyIdentity();
    const recipientBinding = await createIdentityBinding({
      bch: recipientBch,
      nostr: recipientNostr,
      issuedAt: 1_794_175_000,
    });

    const guardian = createBchKeyIdentity('chipnet');
    const covenant = instantiateIdentityAnchor(guardian.pkhHex, provider);
    const nftCommitmentHex = encodeIdentityNftCommitment({
      nostrPubkeyHex: senderNostr.pubkeyHex,
      ownerPkhHex: senderBch.pkhHex,
      sequence: 1n,
    });

    // Fund sender with a vout === 0 BCH UTXO (allows genesis CashTokens Identity NFT mint!)
    const genesisFundingUtxo = provider.addUtxo(senderBch.bchAddress, {
      txid: '11'.repeat(32),
      vout: 0,
      satoshis: 50_000n,
    });

    const anchorBuilt = buildIdentityAnchorTx({
      provider,
      senderAddress: senderBch.bchAddress,
      utxos: [genesisFundingUtxo],
      bindingHashHex: senderBinding.bindingHashHex,
      privateKey: senderBch.privateKey,
      mintIdentityNft: {
        covenantTokenAddress: covenant.tokenAddress,
        commitmentHex: nftCommitmentHex,
      },
    });

    expect(anchorBuilt.signedHex).toBeDefined();
    const anchorVm = verifySignedBchTransactionVm(
      anchorBuilt.signedHex!,
      anchorBuilt.sourceOutputs,
    );
    expect(anchorVm.valid).toBe(true);

    const extracted = extractBlazeCommitmentsFromTxHex(anchorBuilt.signedHex!);
    expect(extracted.commitments).toHaveLength(1);
    expect(extracted.commitments[0].prefixHex).toBe(BLAZE_ANCHOR_PREFIX_HEX);
    expect(extracted.commitments[0].hashOrMemoHex).toBe(senderBinding.bindingHashHex);

    const broadcastedAnchorTxid = await provider.sendRawTransaction(anchorBuilt.signedHex!);
    expect(broadcastedAnchorTxid).toBe(anchorBuilt.txid);

    // Fund sender with 100.00 PUSD (10,000 base units) + BCH fee UTXO
    const pusdUtxo = provider.addUtxo(senderBch.bchTokenAddress, {
      txid: '22'.repeat(32),
      vout: 1,
      satoshis: TOKEN_DUST_SATOSHIS,
      token: {
        category: PUSD_CATEGORY_ID,
        amount: parsePusdAmount('100.00'),
      },
    });
    const feeBchUtxo = provider.addUtxo(senderBch.bchAddress, {
      txid: '33'.repeat(32),
      vout: 2,
      satoshis: 25_000n,
    });

    // Send 25.50 PUSD to recipient's verified Nostr identity!
    const payBuilt = buildIdentityPaymentTx({
      provider,
      senderAddress: senderBch.bchAddress,
      senderTokenAddress: senderBch.bchTokenAddress,
      recipientBinding,
      asset: 'PUSD',
      amountBaseUnits: parsePusdAmount('25.50'),
      utxos: [pusdUtxo, feeBchUtxo],
      memo: 'Invoice #BLAZE-2026',
      privateKey: senderBch.privateKey,
      nowTimestamp: 1_794_175_100,
    });

    expect(payBuilt.signedHex).toBeDefined();
    const payVm = verifySignedBchTransactionVm(payBuilt.signedHex!, payBuilt.sourceOutputs);
    expect(payVm.valid).toBe(true);

    await provider.sendRawTransaction(payBuilt.signedHex!);

    // Confirm recipient received 25.50 PUSD and sender received 74.50 PUSD token change!
    const recipientUtxos = await provider.getUtxos(recipientBch.bchTokenAddress);
    const recipientPusd = recipientUtxos
      .filter((u) => u.token?.category === PUSD_CATEGORY_ID)
      .reduce((acc, u) => acc + (u.token?.amount ?? 0n), 0n);
    expect(recipientPusd).toBe(2550n);

    const senderChangeUtxos = await provider.getUtxos(senderBch.bchTokenAddress);
    const senderRemainingPusd = senderChangeUtxos
      .filter((u) => u.token?.category === PUSD_CATEGORY_ID)
      .reduce((acc, u) => acc + (u.token?.amount ?? 0n), 0n);
    expect(senderRemainingPusd).toBe(7450n);
  });

  it('4. enforces CashScript 0.14.0 IdentityAnchor.cash covenant rotation, unauthorized rejection, guardian recovery & revocation', async () => {
    const provider = new MockNetworkProvider();
    const owner1 = createBchKeyIdentity('chipnet');
    const nostr1 = createNostrKeyIdentity();
    const owner2 = createBchKeyIdentity('chipnet');
    const nostr2 = createNostrKeyIdentity();
    const owner3 = createBchKeyIdentity('chipnet');
    const nostr3 = createNostrKeyIdentity();
    const guardian = createBchKeyIdentity('chipnet');
    const attacker = createBchKeyIdentity('chipnet');

    const contract = instantiateIdentityAnchor(guardian.pkhHex, provider);
    const categoryId = 'aa'.repeat(32);

    const initialCommitment = encodeIdentityNftCommitment({
      nostrPubkeyHex: nostr1.pubkeyHex,
      ownerPkhHex: owner1.pkhHex,
      sequence: 1n,
    });

    provider.addUtxo(contract.tokenAddress, {
      txid: 'bb'.repeat(32),
      vout: 0,
      satoshis: 1000n,
      token: {
        category: categoryId,
        amount: 0n,
        nft: {
          capability: 'mutable',
          commitment: initialCommitment,
        },
      },
    });

    const fundOwnerFee = (owner: typeof owner1) =>
      provider.addUtxo(owner.bchAddress, {
        ...randomUtxo({ satoshis: 15_000n }),
        lockingBytecode: addressToLockingBytecodeHex(owner.bchAddress),
      });

    // 4a. Unauthorized key rotation by attacker MUST fail CashScript VM evaluation
    const [utxoBeforeAttack] = await contract.getUtxos();
    await expect(
      executeRotateIdentity({
        contract,
        anchorUtxo: utxoBeforeAttack,
        feeUtxo: fundOwnerFee(attacker),
        feePayerPrivateKey: attacker.privateKey!,
        feeChangeAddress: attacker.bchAddress,
        currentOwnerPublicKeyHex: attacker.publicKeyCompressedHex,
        currentOwnerPrivateKey: attacker.privateKey!,
        currentNostrPubkeyHex: nostr1.pubkeyHex,
        nextNostrPubkeyHex: nostr2.pubkeyHex,
        nextOwnerPkhHex: attacker.pkhHex,
      }),
    ).rejects.toThrow();

    // 4b. Authorized key rotation by owner1 -> owner2 + nostr2 (sequence 1 -> 2)
    const [anchorUtxo1] = await contract.getUtxos();
    const rotated = await executeRotateIdentity({
      contract,
      anchorUtxo: anchorUtxo1,
      feeUtxo: fundOwnerFee(owner1),
      feePayerPrivateKey: owner1.privateKey!,
      feeChangeAddress: owner1.bchAddress,
      currentOwnerPublicKeyHex: owner1.publicKeyCompressedHex,
      currentOwnerPrivateKey: owner1.privateKey!,
      currentNostrPubkeyHex: nostr1.pubkeyHex,
      nextNostrPubkeyHex: nostr2.pubkeyHex,
      nextOwnerPkhHex: owner2.pkhHex,
    });
    expect(rotated.nextSequence).toBe(2n);

    const [anchorUtxo2] = await contract.getUtxos();
    expect(decodeIdentityNftCommitment(anchorUtxo2.token!.nft!.commitment).sequence).toBe(2n);

    // 4c. Guardian recovery (`recoverIdentity`) -> owner3 + nostr3 (sequence 2 -> 3)
    const recovered = await executeGuardianRecovery({
      contract,
      anchorUtxo: anchorUtxo2,
      feeUtxo: fundOwnerFee(guardian),
      feePayerPrivateKey: guardian.privateKey!,
      feeChangeAddress: guardian.bchAddress,
      guardianPublicKeyHex: guardian.publicKeyCompressedHex,
      guardianPrivateKey: guardian.privateKey!,
      recoveredNostrPubkeyHex: nostr3.pubkeyHex,
      recoveredOwnerPkhHex: owner3.pkhHex,
    });
    expect(recovered.nextSequence).toBe(3n);

    // 4d. Permanent self-sovereign revocation (`revokeIdentity`) by recovered owner3
    const [anchorUtxo3] = await contract.getUtxos();
    const revokeTx = await executeRevokeIdentity({
      contract,
      anchorUtxo: anchorUtxo3,
      feeUtxo: fundOwnerFee(owner3),
      feePayerPrivateKey: owner3.privateKey!,
      feeChangeAddress: owner3.bchAddress,
      currentOwnerPublicKeyHex: owner3.publicKeyCompressedHex,
      currentOwnerPrivateKey: owner3.privateKey!,
      currentNostrPubkeyHex: nostr3.pubkeyHex,
    });

    expect((await contract.getUtxos()).length).toBe(0);
    const revokeOpReturn = decodeBlazeOpReturn(revokeTx.outputs[0].lockingBytecode, 0);
    expect(revokeOpReturn?.type).toBe('revoke');
    expect(revokeOpReturn?.prefixHex).toBe(BLAZE_REVOKE_PREFIX_HEX);
  });

  it('5. publishes & resolves identities over Nostr relay AND executes full WizardConnect NIP-59 BIP32 xpub handshake + PUSD signing', async () => {
    // 5a. Nostr NIP-78 publish & forward/reverse discovery
    const merchantBch = createBchKeyIdentity('mainnet');
    const merchantNostr = createNostrKeyIdentity();
    const merchantBindingV1 = await createIdentityBinding({
      bch: merchantBch,
      nostr: merchantNostr,
      displayName: 'Satoshi Coffee Roasters',
      sequence: 1,
      issuedAt: 1_794_175_000,
    });

    const pubRes = await publishIdentityBinding(merchantBindingV1, [relay.url]);
    expect(pubRes.publishedRelays).toContain(relay.url);

    const resolvedByNpub = await resolveIdentityByNostr(merchantNostr.npub, [relay.url]);
    expect(resolvedByNpub?.payload.bch_token_address).toBe(merchantBch.bchTokenAddress);

    const resolvedByBch = await resolveIdentityByBchAddress(merchantBch.bchAddress, [relay.url]);
    expect(resolvedByBch?.payload.nostr_npub).toBe(merchantNostr.npub);

    // Publish rotated sequence 2 binding -> NIP-33 replaceable query returns sequence 2
    const merchantBchV2 = createBchKeyIdentity('mainnet');
    const merchantBindingV2 = await createIdentityBinding({
      bch: merchantBchV2,
      nostr: merchantNostr,
      displayName: 'Satoshi Coffee Roasters',
      sequence: 2,
      issuedAt: 1_794_175_200,
    });
    await publishIdentityBinding(merchantBindingV2, [relay.url]);
    const latestResolved = await resolveIdentityByNostr(merchantNostr.npub, [relay.url]);
    expect(latestResolved?.payload.sequence).toBe(2);
    expect(latestResolved?.payload.bch_token_address).toBe(merchantBchV2.bchTokenAddress);

    // 5b. Full WizardConnect (`@wizardconnect/core` + `@wizardconnect/dapp` + `@wizardconnect/wallet`)
    //     NIP-59 gift-wrapped handshake + BIP32 xpub address derivation + PUSD payment signing!
    const seed = generatePrivateKey(); // 32-byte BIP32 entropy seed
    const walletAdapter = new NonCustodialBip32WizardWalletAdapter({
      seed,
      network: 'mainnet',
      walletName: 'Paytaca / Selene Compatible HD Wallet',
    });
    const walletManager = new WalletConnectionManager(walletAdapter);

    // Auto-approve incoming WizardConnect transaction sign requests with real BIP32 P2PKH signatures
    walletManager.on('pendingSignRequest', async (pending) => {
      const signed = await walletAdapter.signTransaction(pending.request);
      await walletManager.sendSignResponse(
        pending.connectionId,
        pending.request.sequence,
        signed.signedTransaction,
      );
    });

    const { manager: dappManager, relay: dappRelay } = createProgrammaticWizardDapp({
      dappName: 'CashLink DID Test Suite',
      relayUrls: [relay.url],
    });

    expect(dappRelay.uri.startsWith(`wiz://127.0.0.1:${relay.port}`)).toBe(true);

    try {
      const walletReadyPromise = new Promise<void>((resolve, reject) => {
        const timer = setTimeout(
          () => reject(new Error('WizardConnect walletready timed out')),
          10_000,
        );
        dappManager.once('walletready', () => {
          clearTimeout(timer);
          resolve();
        });
      });

      walletManager.connect(dappRelay.uri);
      await walletReadyPromise;

      expect(dappManager.isWalletDiscovered()).toBe(true);
      expect(dappManager.walletName).toBe('Paytaca / Selene Compatible HD Wallet');

      // Derive user's BCH identity from WizardConnect BIP32 xpub with zero round-trips!
      const connectedBch = deriveBchIdentityFromWizardManager(dappManager, 'mainnet', 0n);
      expect(connectedBch).not.toBeNull();
      const expectedWalletPub = walletAdapter.getPublicKey(DerivationPath.Receive, 0n);
      expect(connectedBch!.publicKeyCompressedHex).toBe(
        Buffer.from(expectedWalletPub).toString('hex'),
      );

      // Build an unsigned PUSD payment to merchantBindingV2 and sign it over WizardConnect!
      const provider = new MockNetworkProvider();
      provider.network = Network.MAINNET;
      const wcPusdUtxo = provider.addUtxo(connectedBch!.bchTokenAddress, {
        txid: '44'.repeat(32),
        vout: 0,
        satoshis: TOKEN_DUST_SATOSHIS,
        token: {
          category: PUSD_CATEGORY_ID,
          amount: parsePusdAmount('50.00'),
        },
      });
      const wcFeeUtxo = provider.addUtxo(connectedBch!.bchAddress, {
        txid: '55'.repeat(32),
        vout: 1,
        satoshis: 20_000n,
      });

      const unsignedPay = buildIdentityPaymentTx({
        provider,
        senderAddress: connectedBch!.bchAddress,
        senderTokenAddress: connectedBch!.bchTokenAddress,
        recipientBinding: latestResolved!,
        asset: 'PUSD',
        amountBaseUnits: parsePusdAmount('15.75'),
        utxos: [wcPusdUtxo, wcFeeUtxo],
        memo: 'WC2-NIP59-PUSD',
        nowTimestamp: 1_794_175_300,
      });

      const signResp = await requestWizardConnectSignature({
        manager: dappManager,
        wcTransaction: unsignedPay.wcTransaction,
        inputPaths: unsignedPay.inputPaths,
      });

      expect(signResp.error).toBeUndefined();
      expect(signResp.signedTransaction.length).toBeGreaterThan(200);

      // Verify the WizardConnect-signed transaction inside libauth's consensus BCH 2025 VM!
      const vmVerification = verifySignedBchTransactionVm(
        signResp.signedTransaction,
        unsignedPay.sourceOutputs,
      );
      expect(vmVerification.valid).toBe(true);
    } finally {
      walletManager.disconnectAll();
      await new Promise((resolve) => setTimeout(resolve, 120));
      dappManager.destroy();
      dappRelay.cleanup();
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
  });
});
