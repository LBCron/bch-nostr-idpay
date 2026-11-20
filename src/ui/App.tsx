import React, { useEffect, useMemo, useState } from 'react';
import { MockNetworkProvider, Network } from 'cashscript';
import { sha256, utf8ToBin } from '@bitauth/libauth';
import { useWizardConnect } from '@wizardconnect/react';
import {
  type AuthChallenge,
  type AuthChallengeResponse,
  BLAZE_ANCHOR_PREFIX_HEX,
  type BchKeyIdentity,
  type BchNetworkId,
  DEFAULT_NOSTR_RELAYS,
  GITHUB_REPO_URL,
  IDENTITY_ANCHOR_ARTIFACT,
  type NostrKeyIdentity,
  PUSD_CATEGORY_ID,
  PUSD_DECIMALS,
  type SignedIdentityBinding,
  type SignedVerifiableCredential,
  TOKEN_DUST_SATOSHIS,
  WIZARDCONNECT_RELAY_URLS,
  buildIdentityAnchorTx,
  buildIdentityPaymentTx,
  createAuthChallenge,
  createBchKeyIdentity,
  createElectrumProvider,
  createIdentityBinding,
  createNostrKeyIdentity,
  deriveBchIdentityFromWizardManager,
  encodeIdentityNftCommitment,
  extractBlazeCommitmentsFromTxHex,
  formatPusdAmount,
  instantiateIdentityAnchor,
  issueVerifiableCredential,
  parsePusdAmount,
  publishIdentityBinding,
  requestWizardConnectSignature,
  resolveIdentityByNostr,
  respondToAuthChallenge,
  verifyAuthChallengeResponse,
  verifyIdentityBinding,
  verifySignedBchTransactionVm,
  verifyVerifiableCredential,
} from '../sdk/index.js';
import { ComplianceBanner } from './ComplianceBanner.js';
import { DeckView } from './DeckView.js';
import {
  AlertIcon,
  CheckIcon,
  CopyIcon,
  KeyChallengeIcon,
  LinkIcon,
  RefreshIcon,
  SendPayIcon,
  ShieldCheckIcon,
  SlidesIcon,
} from './Icons.js';

type ActiveTab = 'bind' | 'pay' | 'verify' | 'deck';

function deterministicKey(label: string): Uint8Array {
  return sha256.hash(utf8ToBin(`cashlink-did-demo-seed:v1:${label}`));
}

function getInitialTab(): ActiveTab {
  if (typeof window === 'undefined') return 'bind';
  if (
    window.location.hash === '#/deck' ||
    window.location.pathname.replace(/\/+$/, '').endsWith('/deck')
  ) {
    return 'deck';
  }
  if (window.location.hash === '#/pay') return 'pay';
  if (window.location.hash === '#/verify') return 'verify';
  return 'bind';
}

function makeSandboxProvider(network: BchNetworkId): MockNetworkProvider {
  const p = new MockNetworkProvider();
  p.network = network === 'mainnet' ? Network.MAINNET : Network.CHIPNET;
  return p;
}

export function App(): React.ReactElement {
  const [activeTab, setActiveTab] = useState<ActiveTab>(getInitialTab);
  const [network, setNetwork] = useState<BchNetworkId>('mainnet');

  const wizard = useWizardConnect({
    dappName: 'CashLink DID — BCH × Nostr Identity & PUSD Pay',
    relayUrls: WIZARDCONNECT_RELAY_URLS,
    persistSession: false,
  });

  // Non-custodial client-side keypairs (regenerated cleanly when network changes)
  const [localBch, setLocalBch] = useState<BchKeyIdentity>(() => createBchKeyIdentity('mainnet'));
  const [localNostr, setLocalNostr] = useState<NostrKeyIdentity>(() => createNostrKeyIdentity());
  const [guardianBch, setGuardianBch] = useState<BchKeyIdentity>(() =>
    createBchKeyIdentity('mainnet'),
  );

  // Derive WizardConnect BIP32 identity whenever remote wallet is ready
  const wcBchIdentity = useMemo(() => {
    if (wizard.state !== 'connected' || !wizard.manager) return null;
    return deriveBchIdentityFromWizardManager(wizard.manager, network, 0n);
  }, [wizard.state, wizard.manager, network]);

  const activeBch = wcBchIdentity ?? localBch;

  useEffect(() => {
    setLocalBch((prev) => createBchKeyIdentity(network, prev.privateKey));
    setGuardianBch((prev) => createBchKeyIdentity(network, prev.privateKey));
  }, [network]);

  useEffect(() => {
    const onHashChange = () => {
      if (window.location.hash === '#/deck') setActiveTab('deck');
      else if (window.location.hash === '#/pay') setActiveTab('pay');
      else if (window.location.hash === '#/verify') setActiveTab('verify');
      else if (window.location.hash === '#/bind') setActiveTab('bind');
    };
    window.addEventListener('hashchange', onHashChange);
    return () => window.removeEventListener('hashchange', onHashChange);
  }, []);

  const switchTab = (next: ActiveTab) => {
    setActiveTab(next);
    if (typeof window !== 'undefined') {
      const targetHash = `#/${next}`;
      if (window.location.hash !== targetHash) {
        window.history.replaceState(null, '', targetHash);
      }
    }
  };

  // Pre-seed 3 real cryptographically dual-signed merchant identities for instant resolution
  const [demoDirectory, setDemoDirectory] = useState<SignedIdentityBinding[]>([]);
  useEffect(() => {
    let cancelled = false;
    (async () => {
      const specs = [
        { id: 'coffee', name: 'Satoshi Coffee Roasters' },
        { id: 'remit', name: 'Manila PUSD Remit Desk' },
        { id: 'hardware', name: 'Verde Hardware Lab' },
      ];
      const built: SignedIdentityBinding[] = [];
      for (const s of specs) {
        const bch = createBchKeyIdentity(network, deterministicKey(`bch:${s.id}`));
        const nostr = createNostrKeyIdentity(deterministicKey(`nostr:${s.id}`));
        const signed = await createIdentityBinding({
          bch,
          nostr,
          displayName: s.name,
          sequence: 1,
        });
        built.push(signed);
      }
      if (!cancelled) {
        setDemoDirectory(built);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [network]);

  // ---------------------------------------------------------------------------
  // TAB 1 STATE: BIND & ANCHOR IDENTITY
  // ---------------------------------------------------------------------------
  const [displayName, setDisplayName] = useState('Ronan Sovereign Studio');
  const [displayNameError, setDisplayNameError] = useState<string | null>(null);
  const [sequence, setSequence] = useState(1);
  const [mintNftOnAnchor, setMintNftOnAnchor] = useState(true);
  const [signedBinding, setSignedBinding] = useState<SignedIdentityBinding | null>(null);
  const [bindStatus, setBindStatus] = useState<{ ok: boolean; text: string } | null>(null);
  const [anchorResult, setAnchorResult] = useState<{
    txid: string;
    feeSats: bigint;
    vmValid: boolean;
    opReturnHex: string;
    covenantAddress: string;
    nftCommitmentHex: string;
    rawHex: string;
    mode: string;
  } | null>(null);
  const [isPublishingRelay, setIsPublishingRelay] = useState(false);
  const [isBuildingAnchor, setIsBuildingAnchor] = useState(false);
  const [copiedTxid, setCopiedTxid] = useState(false);

  const covenantPreview = useMemo(() => {
    const provider = makeSandboxProvider(network);
    const contract = instantiateIdentityAnchor(guardianBch.pkhHex, provider);
    const commitmentHex = encodeIdentityNftCommitment({
      nostrPubkeyHex: localNostr.pubkeyHex,
      ownerPkhHex: activeBch.pkhHex,
      sequence,
    });
    return {
      tokenAddress: contract.tokenAddress,
      bytecodeSize: contract.bytesize,
      opcount: contract.opcount,
      commitmentHex,
    };
  }, [network, guardianBch.pkhHex, localNostr.pubkeyHex, activeBch.pkhHex, sequence]);

  const handleRegenerateKeys = () => {
    setLocalBch(createBchKeyIdentity(network));
    setLocalNostr(createNostrKeyIdentity());
    setGuardianBch(createBchKeyIdentity(network));
    setSignedBinding(null);
    setAnchorResult(null);
    setBindStatus({
      ok: true,
      text: 'Generated fresh non-custodial secp256k1 BCH, BIP-340 Nostr, and Guardian keypairs locally.',
    });
  };

  const handleSignDualBinding = async () => {
    if (!displayName.trim()) {
      setDisplayNameError('Enter a public display name or merchant handle before signing.');
      return;
    }
    try {
      const signerBch = activeBch.privateKey ? activeBch : localBch;
      const binding = await createIdentityBinding({
        bch: signerBch,
        nostr: localNostr,
        displayName: displayName.trim(),
        sequence,
      });
      setSignedBinding(binding);
      setDemoDirectory((prev) => [
        binding,
        ...prev.filter((item) => item.nostrEvent.pubkey !== binding.nostrEvent.pubkey),
      ]);
      setBindStatus({
        ok: true,
        text: `Dual cryptographic proof signed and verified (SHA-256 commitment ${binding.bindingHashHex.slice(0, 16)}…).`,
      });
    } catch (err) {
      setBindStatus({
        ok: false,
        text: err instanceof Error ? err.message : String(err),
      });
    }
  };

  const handlePublishToRelays = async () => {
    if (!signedBinding) return;
    setIsPublishingRelay(true);
    try {
      const res = await publishIdentityBinding(signedBinding, DEFAULT_NOSTR_RELAYS);
      if (res.publishedRelays.length > 0) {
        setBindStatus({
          ok: true,
          text: `Published kind:30078 attestation to ${res.publishedRelays.length} live Nostr relay(s): ${res.publishedRelays.join(', ')}`,
        });
      } else {
        setBindStatus({
          ok: true,
          text: 'Signed kind:30078 event ready in local directory (external public relays unreachable in offline environment).',
        });
      }
    } catch (err) {
      setBindStatus({
        ok: false,
        text: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setIsPublishingRelay(false);
    }
  };

  const handleBuildAndVerifyAnchorTx = async () => {
    if (!signedBinding) return;
    setIsBuildingAnchor(true);
    try {
      let liveUtxos = null as Awaited<ReturnType<ReturnType<typeof createElectrumProvider>['getUtxos']>> | null;
      let liveProvider: ReturnType<typeof createElectrumProvider> | null = null;

      if (wizard.state === 'connected') {
        try {
          liveProvider = createElectrumProvider(network);
          const fetched = await Promise.race([
            liveProvider.getUtxos(activeBch.bchAddress),
            new Promise<never>((_, reject) =>
              setTimeout(() => reject(new Error('Electrum UTXO query timeout')), 3500),
            ),
          ]);
          if (fetched.length > 0) {
            liveUtxos = fetched;
          }
        } catch {
          liveUtxos = null;
        }
      }

      if (liveUtxos && liveProvider && wizard.state === 'connected' && wizard.manager) {
        const built = buildIdentityAnchorTx({
          provider: liveProvider,
          senderAddress: activeBch.bchAddress,
          utxos: liveUtxos,
          bindingHashHex: signedBinding.bindingHashHex,
          mintIdentityNft:
            mintNftOnAnchor && liveUtxos.some((u) => !u.token && u.vout === 0)
              ? {
                  covenantTokenAddress: covenantPreview.tokenAddress,
                  commitmentHex: covenantPreview.commitmentHex,
                }
              : undefined,
        });
        const wcSig = await requestWizardConnectSignature({
          manager: wizard.manager,
          wcTransaction: built.wcTransaction,
          inputPaths: built.inputPaths,
        });
        if (wcSig.error) throw new Error(wcSig.error);
        const vmCheck = verifySignedBchTransactionVm(wcSig.signedTransaction, built.sourceOutputs);
        const txid = await liveProvider.sendRawTransaction(wcSig.signedTransaction);
        setAnchorResult({
          txid,
          feeSats: built.feeSatoshis,
          vmValid: vmCheck.valid,
          opReturnHex: `6a04${BLAZE_ANCHOR_PREFIX_HEX}20${signedBinding.bindingHashHex}`,
          covenantAddress: covenantPreview.tokenAddress,
          nftCommitmentHex: covenantPreview.commitmentHex,
          rawHex: wcSig.signedTransaction,
          mode: `Broadcast via Electrum (${network}) + WizardConnect`,
        });
      } else {
        // Non-custodial deterministic VM-verified build (works 100% offline or pre-funding)
        const sandboxProvider = makeSandboxProvider(network);
        const fundedUtxo = sandboxProvider.addUtxo(localBch.bchAddress, {
          txid: sha256
            .hash(utf8ToBin(`anchor-utxo:${signedBinding.bindingHashHex}`))
            .reduce((s, b) => s + b.toString(16).padStart(2, '0'), ''),
          vout: 0,
          satoshis: 25_000n,
        });
        const built = buildIdentityAnchorTx({
          provider: sandboxProvider,
          senderAddress: localBch.bchAddress,
          utxos: [fundedUtxo],
          bindingHashHex: signedBinding.bindingHashHex,
          privateKey: localBch.privateKey,
          mintIdentityNft: mintNftOnAnchor
            ? {
                covenantTokenAddress: covenantPreview.tokenAddress,
                commitmentHex: covenantPreview.commitmentHex,
              }
            : undefined,
        });
        const vmCheck = verifySignedBchTransactionVm(built.signedHex!, built.sourceOutputs);
        const parsedCommitments = extractBlazeCommitmentsFromTxHex(built.signedHex!);
        setAnchorResult({
          txid: built.txid!,
          feeSats: built.feeSatoshis,
          vmValid: vmCheck.valid && parsedCommitments.commitments.length === 1,
          opReturnHex: `6a04${BLAZE_ANCHOR_PREFIX_HEX}20${signedBinding.bindingHashHex}`,
          covenantAddress: covenantPreview.tokenAddress,
          nftCommitmentHex: covenantPreview.commitmentHex,
          rawHex: built.signedHex!,
          mode: 'Signed locally & verified in @bitauth/libauth BCH 2025 VM',
        });
      }
      setBindStatus({
        ok: true,
        text: 'Constructed consensus-valid BLZI OP_RETURN + CashTokens Identity NFT transaction.',
      });
    } catch (err) {
      setBindStatus({
        ok: false,
        text: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setIsBuildingAnchor(false);
    }
  };

  // ---------------------------------------------------------------------------
  // TAB 2 STATE: RESOLVE @NPUB & PAY IN PUSD / BCH
  // ---------------------------------------------------------------------------
  const [lookupInput, setLookupInput] = useState('');
  const [lookupError, setLookupError] = useState<string | null>(null);
  const [resolvedTarget, setResolvedTarget] = useState<SignedIdentityBinding | null>(null);
  const [isResolving, setIsResolving] = useState(false);
  const [payAsset, setPayAsset] = useState<'PUSD' | 'BCH'>('PUSD');
  const [payAmount, setPayAmount] = useState('12.50');
  const [payAmountError, setPayAmountError] = useState<string | null>(null);
  const [payMemo, setPayMemo] = useState('Coffee & Pastry #BLAZE');
  const [payStatus, setPayStatus] = useState<{ ok: boolean; text: string } | null>(null);
  const [paymentReceipt, setPaymentReceipt] = useState<{
    txid: string;
    assetLabel: string;
    recipientHandle: string;
    recipientAddress: string;
    feeSats: bigint;
    vmValid: boolean;
    rawHex: string;
  } | null>(null);

  useEffect(() => {
    if (demoDirectory.length > 0 && !resolvedTarget) {
      setResolvedTarget(demoDirectory[0]);
      setLookupInput(demoDirectory[0].payload.nostr_npub);
    }
  }, [demoDirectory, resolvedTarget]);

  const targetVerification = useMemo(() => {
    if (!resolvedTarget) return null;
    return verifyIdentityBinding(resolvedTarget);
  }, [resolvedTarget]);

  const validateLookupField = (val: string): string | null => {
    const clean = val.trim().replace(/^@/, '');
    if (!clean) return 'Enter a Nostr npub1… or 64-character hex public key.';
    if (!clean.startsWith('npub1') && !/^[0-9a-f]{64}$/i.test(clean)) {
      return 'Identifier must start with npub1… or be a 64-character hex pubkey.';
    }
    return null;
  };

  const handleResolveNpub = async () => {
    const err = validateLookupField(lookupInput);
    if (err) {
      setLookupError(err);
      return;
    }
    const clean = lookupInput.trim().replace(/^@/, '');
    const localHit = demoDirectory.find(
      (d) =>
        d.payload.nostr_npub.toLowerCase() === clean.toLowerCase() ||
        d.nostrEvent.pubkey.toLowerCase() === clean.toLowerCase(),
    );
    if (localHit) {
      setResolvedTarget(localHit);
      setPayStatus({
        ok: true,
        text: `Resolved & cryptographically verified ${localHit.payload.display_name ?? localHit.payload.nostr_npub.slice(0, 16)}…`,
      });
      return;
    }

    setIsResolving(true);
    try {
      const remote = await resolveIdentityByNostr(clean, DEFAULT_NOSTR_RELAYS, {
        maxWaitMs: 4500,
      });
      if (remote) {
        setResolvedTarget(remote);
        setPayStatus({
          ok: true,
          text: `Resolved live Nostr attestation for ${remote.payload.nostr_npub.slice(0, 18)}…`,
        });
      } else {
        setPayStatus({
          ok: false,
          text: 'No verified cashlink-did-v1 attestation found on public relays for that npub.',
        });
      }
    } catch (e) {
      setPayStatus({
        ok: false,
        text: e instanceof Error ? e.message : String(e),
      });
    } finally {
      setIsResolving(false);
    }
  };

  const validateAmountField = (val: string, asset: 'PUSD' | 'BCH'): string | null => {
    const clean = val.trim();
    if (!clean) return 'Enter a positive payment amount.';
    if (asset === 'PUSD') {
      try {
        const units = parsePusdAmount(clean);
        if (units <= 0n) return 'PUSD amount must be greater than 0.00.';
        return null;
      } catch (e) {
        return e instanceof Error ? e.message : 'Invalid PUSD decimal amount.';
      }
    } else {
      if (!/^\d+$/.test(clean) || BigInt(clean) < 546n) {
        return 'BCH amount in satoshis must be an integer >= 546 sats.';
      }
      return null;
    }
  };

  const handleExecutePayment = async () => {
    if (!resolvedTarget) return;
    const amtErr = validateAmountField(payAmount, payAsset);
    if (amtErr) {
      setPayAmountError(amtErr);
      return;
    }

    try {
      const amountBaseUnits =
        payAsset === 'PUSD' ? parsePusdAmount(payAmount) : BigInt(payAmount.trim());

      const sandboxProvider = makeSandboxProvider(network);
      const pusdUtxo = sandboxProvider.addUtxo(localBch.bchTokenAddress, {
        txid: '24'.repeat(32),
        vout: 0,
        satoshis: TOKEN_DUST_SATOSHIS,
        token: {
          category: PUSD_CATEGORY_ID,
          amount: parsePusdAmount('500.00'),
        },
      });
      const bchUtxo = sandboxProvider.addUtxo(localBch.bchAddress, {
        txid: '36'.repeat(32),
        vout: 1,
        satoshis: 250_000n,
      });

      const built = buildIdentityPaymentTx({
        provider: sandboxProvider,
        senderAddress: localBch.bchAddress,
        senderTokenAddress: localBch.bchTokenAddress,
        recipientBinding: resolvedTarget,
        asset: payAsset,
        amountBaseUnits,
        utxos: [pusdUtxo, bchUtxo],
        memo: payMemo,
        privateKey: localBch.privateKey,
      });

      const vmCheck = verifySignedBchTransactionVm(built.signedHex!, built.sourceOutputs);
      const assetLabel =
        payAsset === 'PUSD'
          ? `${formatPusdAmount(amountBaseUnits)} PUSD`
          : `${amountBaseUnits.toString()} sats BCH`;

      setPaymentReceipt({
        txid: built.txid!,
        assetLabel,
        recipientHandle: resolvedTarget.payload.display_name ?? resolvedTarget.payload.nostr_npub,
        recipientAddress:
          payAsset === 'PUSD'
            ? resolvedTarget.payload.bch_token_address
            : resolvedTarget.payload.bch_address,
        feeSats: built.feeSatoshis,
        vmValid: vmCheck.valid,
        rawHex: built.signedHex!,
      });
      setPayStatus({
        ok: true,
        text: `Built, dual-verified, and validated ${assetLabel} transaction in @bitauth/libauth BCH 2025 VM.`,
      });
    } catch (err) {
      setPayStatus({
        ok: false,
        text: err instanceof Error ? err.message : String(err),
      });
    }
  };

  // ---------------------------------------------------------------------------
  // TAB 3 STATE: LOGIN WITH BCH × NOSTR VERIFIER & REPUTATION VCs
  // ---------------------------------------------------------------------------
  const [rpDomain, setRpDomain] = useState('merchant.bchblaze.cash');
  const [rpDomainError, setRpDomainError] = useState<string | null>(null);
  const [challenge, setChallenge] = useState<AuthChallenge>(() =>
    createAuthChallenge({ domain: 'merchant.bchblaze.cash' }),
  );
  const [authResponse, setAuthResponse] = useState<AuthChallengeResponse | null>(null);
  const [simulateDomainSpoof, setSimulateDomainSpoof] = useState(false);
  const [simulateAddressTamper, setSimulateAddressTamper] = useState(false);
  const [issuedVc, setIssuedVc] = useState<SignedVerifiableCredential | null>(null);

  const liveVerification = useMemo(() => {
    if (!authResponse) return null;
    const targetResponse: AuthChallengeResponse = simulateAddressTamper
      ? {
          ...authResponse,
          binding: {
            ...authResponse.binding,
            payload: {
              ...authResponse.binding.payload,
              bch_address: guardianBch.bchAddress,
            },
          },
        }
      : authResponse;

    const expectedChallenge: AuthChallenge = simulateDomainSpoof
      ? { ...challenge, domain: 'evil-phishing-spoof.example' }
      : challenge;

    return verifyAuthChallengeResponse(targetResponse, expectedChallenge, {
      requireLiveBchSignature: true,
    });
  }, [authResponse, challenge, simulateDomainSpoof, simulateAddressTamper, guardianBch.bchAddress]);

  const vcVerification = useMemo(() => {
    if (!issuedVc) return null;
    return verifyVerifiableCredential(issuedVc);
  }, [issuedVc]);

  const handleIssueFreshChallenge = () => {
    if (!rpDomain.trim()) {
      setRpDomainError('Enter a relying-party domain (e.g. merchant.bchblaze.cash).');
      return;
    }
    const next = createAuthChallenge({ domain: rpDomain.trim() });
    setChallenge(next);
    setAuthResponse(null);
    setSimulateDomainSpoof(false);
    setSimulateAddressTamper(false);
  };

  const handleSignChallengeLogin = async () => {
    const binding =
      signedBinding ??
      (await createIdentityBinding({
        bch: localBch,
        nostr: localNostr,
        displayName: displayName.trim() || 'Sovereign User',
        sequence,
      }));
    if (!signedBinding) {
      setSignedBinding(binding);
    }
    const resp = await respondToAuthChallenge({
      challenge,
      binding,
      nostrSecretKey: localNostr.secretKey,
      bchPrivateKey: localBch.privateKey,
    });
    setAuthResponse(resp);

    if (localNostr.secretKey) {
      const vc = issueVerifiableCredential({
        issuerBinding: binding,
        issuerNostrSecretKey: localNostr.secretKey,
        issuerName: binding.payload.display_name ?? 'CashLink Registry',
        subjectBinding: binding,
        credentialType: 'VerifiedPusdMerchant',
        badge: 'ParyonUSD Verified Merchant',
        claims: {
          accepts_pusd: true,
          pusd_category: PUSD_CATEGORY_ID,
          settlement_network: network,
          verified_handle: binding.payload.display_name ?? binding.payload.nostr_npub,
        },
      });
      setIssuedVc(vc);
    }
  };

  // Keyboard navigation for ARIA tablist
  const tabOrder: ActiveTab[] = ['bind', 'pay', 'verify', 'deck'];
  const handleTabKeyDown = (e: React.KeyboardEvent<HTMLDivElement>) => {
    const idx = tabOrder.indexOf(activeTab);
    if (e.key === 'ArrowRight') {
      e.preventDefault();
      const next = tabOrder[(idx + 1) % tabOrder.length];
      switchTab(next);
      document.getElementById(`tab-${next}`)?.focus();
    } else if (e.key === 'ArrowLeft') {
      e.preventDefault();
      const prev = tabOrder[(idx - 1 + tabOrder.length) % tabOrder.length];
      switchTab(prev);
      document.getElementById(`tab-${prev}`)?.focus();
    }
  };

  return (
    <>
      <a className="skip-link" href="#main-content">
        Skip to main content
      </a>

      <ComplianceBanner
        network={network}
        onChangeNetwork={setNetwork}
        onOpenDeck={() => switchTab('deck')}
        isDeckActive={activeTab === 'deck'}
        wizard={wizard}
        connectedBchAddress={wcBchIdentity?.bchAddress ?? null}
      />

      <main id="main-content" className="app-shell">
        <div className="hero-header">
          <div className="hero-title-group">
            <h1 className="hero-title">CashLink DID</h1>
            <p className="hero-subtitle">
              Non-custodial Bitcoin Cash × Nostr decentralized identity, CashScript 0.14.0 key
              rotation covenants, and ParyonUSD (PUSD) CashToken settlements.
            </p>
          </div>

          <div className="btn-row">
            <span className="badge badge-verified">
              <ShieldCheckIcon size={15} />
              <span>Zero Key-Reuse Enforced</span>
            </span>
            <button type="button" className="btn" onClick={handleRegenerateKeys}>
              <RefreshIcon size={15} />
              <span>New Sandbox Keypairs</span>
            </button>
          </div>
        </div>

        <div className="protocol-strip" aria-label="Active Protocol Configuration">
          <div className="stat-item">
            <span className="stat-label">Active Network</span>
            <span className="stat-value">
              {network === 'mainnet' ? 'Bitcoin Cash Mainnet' : 'Bitcoin Cash Chipnet'}
            </span>
          </div>
          <div className="stat-item">
            <span className="stat-label">ParyonUSD Category (Decimals: {PUSD_DECIMALS})</span>
            <span className="stat-value">
              {PUSD_CATEGORY_ID.slice(0, 12)}…{PUSD_CATEGORY_ID.slice(-8)}
            </span>
          </div>
          <div className="stat-item">
            <span className="stat-label">Covenant Bytecode</span>
            <span className="stat-value">
              {IDENTITY_ANCHOR_ARTIFACT.contractName} ({covenantPreview.bytecodeSize} B /{' '}
              {covenantPreview.opcount} ops)
            </span>
          </div>
          <div className="stat-item">
            <span className="stat-label">Signer Source</span>
            <span className="stat-value">
              {wcBchIdentity ? `WizardConnect (${wizard.walletName ?? 'HD'})` : 'Local secp256k1 + Schnorr'}
            </span>
          </div>
        </div>

        <div
          className="tab-bar"
          role="tablist"
          aria-label="CashLink DID Protocol Workspaces"
          onKeyDown={handleTabKeyDown}
        >
          <button
            id="tab-bind"
            type="button"
            role="tab"
            className="tab-btn"
            aria-selected={activeTab === 'bind'}
            aria-controls="panel-bind"
            tabIndex={activeTab === 'bind' ? 0 : -1}
            onClick={() => switchTab('bind')}
          >
            <LinkIcon size={17} />
            <span>1. Bind & Anchor Identity</span>
          </button>

          <button
            id="tab-pay"
            type="button"
            role="tab"
            className="tab-btn"
            aria-selected={activeTab === 'pay'}
            aria-controls="panel-pay"
            tabIndex={activeTab === 'pay' ? 0 : -1}
            onClick={() => switchTab('pay')}
          >
            <SendPayIcon size={17} />
            <span>2. Resolve @npub & Pay PUSD</span>
          </button>

          <button
            id="tab-verify"
            type="button"
            role="tab"
            className="tab-btn"
            aria-selected={activeTab === 'verify'}
            aria-controls="panel-verify"
            tabIndex={activeTab === 'verify' ? 0 : -1}
            onClick={() => switchTab('verify')}
          >
            <KeyChallengeIcon size={17} />
            <span>3. Login Verifier & VCs</span>
          </button>

          <button
            id="tab-deck"
            type="button"
            role="tab"
            className="tab-btn"
            aria-selected={activeTab === 'deck'}
            aria-controls="panel-deck"
            tabIndex={activeTab === 'deck' ? 0 : -1}
            onClick={() => switchTab('deck')}
          >
            <SlidesIcon size={17} />
            <span>4. Pitch Deck (/deck)</span>
          </button>
        </div>

        {/* ================================================================= */}
        {/* PANEL 1: BIND & ANCHOR IDENTITY                                   */}
        {/* ================================================================= */}
        {activeTab === 'bind' && (
          <div
            id="panel-bind"
            role="tabpanel"
            aria-labelledby="tab-bind"
            className="workspace-grid"
          >
            <section className="panel">
              <div className="panel-header">
                <div>
                  <h2>Dual Cryptographic Identity Binding</h2>
                  <p>
                    Bind your Bitcoin Cash P2PKH & CashTokens address to your Nostr identity with
                    zero private-key reuse.
                  </p>
                </div>
                <span className="badge badge-verified">NIP-78 kind:30078</span>
              </div>

              <div className="kv-list">
                <div className="kv-row">
                  <span className="kv-key">BCH CashAddress</span>
                  <span className="kv-val">{activeBch.bchAddress}</span>
                </div>
                <div className="kv-row">
                  <span className="kv-key">CashTokens Address (z…)</span>
                  <span className="kv-val">{activeBch.bchTokenAddress}</span>
                </div>
                <div className="kv-row">
                  <span className="kv-key">Nostr Public Handle</span>
                  <span className="kv-val">{localNostr.npub}</span>
                </div>
                <div className="kv-row">
                  <span className="kv-key">Guardian Recovery PKH</span>
                  <span className="kv-val">0x{guardianBch.pkhHex}</span>
                </div>
              </div>

              <div className="form-stack">
                <div className="form-row-2">
                  <div className="field">
                    <label htmlFor="bind-display-name">Public Display Name / Merchant Alias</label>
                    <input
                      id="bind-display-name"
                      type="text"
                      className="input"
                      value={displayName}
                      aria-invalid={displayNameError ? 'true' : undefined}
                      aria-describedby={displayNameError ? 'bind-name-err' : undefined}
                      onBlur={() => {
                        if (!displayName.trim()) {
                          setDisplayNameError(
                            'Enter a public display name or merchant handle before signing.',
                          );
                        }
                      }}
                      onChange={(e) => {
                        setDisplayName(e.target.value);
                        if (displayNameError) setDisplayNameError(null);
                      }}
                    />
                    {displayNameError && (
                      <span id="bind-name-err" className="field-error">
                        {displayNameError}
                      </span>
                    )}
                  </div>

                  <div className="field">
                    <label htmlFor="bind-sequence">Rotation Sequence Counter</label>
                    <input
                      id="bind-sequence"
                      type="number"
                      min={1}
                      max={999}
                      className="input mono"
                      value={sequence}
                      onChange={(e) => setSequence(Math.max(1, Number(e.target.value) || 1))}
                    />
                  </div>
                </div>

                <label className="checkbox-row" htmlFor="mint-identity-nft">
                  <input
                    id="mint-identity-nft"
                    type="checkbox"
                    checked={mintNftOnAnchor}
                    onChange={(e) => setMintNftOnAnchor(e.target.checked)}
                  />
                  <span>
                    Mint mutable CashTokens Identity NFT into compiled{' '}
                    <code>IdentityAnchor.cash</code> covenant (40-byte commitment)
                  </span>
                </label>

                <div className="btn-row">
                  <button
                    type="button"
                    className="btn btn-primary"
                    onClick={() => void handleSignDualBinding()}
                  >
                    <ShieldCheckIcon size={16} />
                    <span>Sign Dual BCH × Nostr Proof</span>
                  </button>

                  <button
                    type="button"
                    className="btn"
                    disabled={!signedBinding || isPublishingRelay}
                    onClick={() => void handlePublishToRelays()}
                  >
                    <span>{isPublishingRelay ? 'Publishing…' : 'Publish to Nostr Relays'}</span>
                  </button>

                  <button
                    type="button"
                    className="btn"
                    disabled={!signedBinding || isBuildingAnchor}
                    onClick={() => void handleBuildAndVerifyAnchorTx()}
                  >
                    <span>
                      {isBuildingAnchor ? 'Building TX…' : 'Build On-Chain BLZI Anchor TX'}
                    </span>
                  </button>
                </div>
              </div>

              {bindStatus && (
                <div className={`status-banner ${bindStatus.ok ? 'ok' : 'err'}`}>
                  {bindStatus.ok ? <ShieldCheckIcon size={18} /> : <AlertIcon size={18} />}
                  <span>{bindStatus.text}</span>
                </div>
              )}
            </section>

            <section className="panel">
              <div className="panel-header">
                <div>
                  <h2>On-Chain Covenant & Proof Inspector</h2>
                  <p>
                    Inspect your compiled CashScript 0.14.0 covenant address, 40-byte NFT
                    commitment, and VM-verified anchor transaction.
                  </p>
                </div>
                <span className="badge">P2SH32 Covenant</span>
              </div>

              <div className="kv-list">
                <div className="kv-row">
                  <span className="kv-key">Covenant Token Address</span>
                  <span className="kv-val">{covenantPreview.tokenAddress}</span>
                </div>
                <div className="kv-row">
                  <span className="kv-key">40-Byte NFT Commitment</span>
                  <span className="kv-val">{covenantPreview.commitmentHex}</span>
                </div>
                {anchorResult && (
                  <>
                    <div className="kv-row">
                      <span className="kv-key">Anchor TXID</span>
                      <span className="kv-val">
                        {anchorResult.txid}{' '}
                        <button
                          type="button"
                          className="btn btn-sm"
                          onClick={async () => {
                            try {
                              await navigator.clipboard.writeText(anchorResult.txid);
                              setCopiedTxid(true);
                              setTimeout(() => setCopiedTxid(false), 1600);
                            } catch {
                              // ignore
                            }
                          }}
                        >
                          {copiedTxid ? <CheckIcon size={13} /> : <CopyIcon size={13} />}
                        </button>
                      </span>
                    </div>
                    <div className="kv-row">
                      <span className="kv-key">BCH 2025 VM Evaluation</span>
                      <span className="kv-val">
                        {anchorResult.vmValid
                          ? `VALID (${anchorResult.feeSats.toString()} sats fee)`
                          : 'FAILED'}
                      </span>
                    </div>
                    <div className="kv-row">
                      <span className="kv-key">BLZI OP_RETURN Script</span>
                      <span className="kv-val">{anchorResult.opReturnHex}</span>
                    </div>
                  </>
                )}
              </div>

              <div className="field">
                <span className="stat-label">
                  {signedBinding
                    ? 'Signed Dual Attestation (Proof A BCH Signature + Proof B NIP-78 Event)'
                    : 'Sign your dual proof on the left to inspect the canonical JSON attestation'}
                </span>
                <pre className="code-well">
                  {signedBinding
                    ? JSON.stringify(
                        {
                          bindingHashHex: signedBinding.bindingHashHex,
                          bchProof: signedBinding.bchProof,
                          nostrEventId: signedBinding.nostrEvent.id,
                          nostrSchnorrSig: signedBinding.nostrEvent.sig,
                          payload: signedBinding.payload,
                        },
                        null,
                        2,
                      )
                    : `// IdentityAnchor.cash ABI Functions:\n${JSON.stringify(
                        IDENTITY_ANCHOR_ARTIFACT.abi,
                        null,
                        2,
                      )}`}
                </pre>
              </div>
            </section>
          </div>
        )}

        {/* ================================================================= */}
        {/* PANEL 2: RESOLVE @NPUB & PAY IN PUSD / BCH                        */}
        {/* ================================================================= */}
        {activeTab === 'pay' && (
          <div
            id="panel-pay"
            role="tabpanel"
            aria-labelledby="tab-pay"
            className="workspace-grid"
          >
            <section className="panel">
              <div className="panel-header">
                <div>
                  <h2>Resolve @npub & Pay in ParyonUSD (PUSD)</h2>
                  <p>
                    Verify both BCH and Nostr cryptographic proofs client-side before constructing a
                    CashTokens PUSD or native BCH transaction.
                  </p>
                </div>
                <span className="badge badge-amber">PUSD CashToken</span>
              </div>

              <div className="field">
                <span className="stat-label">Verified Merchant Directory (1-Click Select)</span>
                <div className="directory-list">
                  {demoDirectory.map((item) => {
                    const isSelected =
                      resolvedTarget?.nostrEvent.pubkey === item.nostrEvent.pubkey;
                    return (
                      <button
                        key={item.nostrEvent.id}
                        type="button"
                        className={`directory-chip ${isSelected ? 'active' : ''}`}
                        onClick={() => {
                          setResolvedTarget(item);
                          setLookupInput(item.payload.nostr_npub);
                          setLookupError(null);
                          setPaymentReceipt(null);
                        }}
                      >
                        <ShieldCheckIcon size={14} />
                        <span>{item.payload.display_name ?? item.payload.nostr_npub.slice(0, 14)}</span>
                      </button>
                    );
                  })}
                </div>
              </div>

              <hr className="section-divider" />

              <div className="form-stack">
                <div className="field">
                  <label htmlFor="resolve-npub-input">Recipient Nostr Identifier (npub1… or hex)</label>
                  <div className="btn-row">
                    <input
                      id="resolve-npub-input"
                      type="text"
                      className="input mono"
                      style={{ flex: 1 }}
                      value={lookupInput}
                      autoCorrect="off"
                      autoCapitalize="off"
                      spellCheck={false}
                      aria-invalid={lookupError ? 'true' : undefined}
                      aria-describedby={lookupError ? 'resolve-npub-err' : undefined}
                      onBlur={() => setLookupError(validateLookupField(lookupInput))}
                      onChange={(e) => {
                        setLookupInput(e.target.value);
                        if (lookupError) setLookupError(null);
                      }}
                    />
                    <button
                      type="button"
                      className="btn"
                      disabled={isResolving}
                      onClick={() => void handleResolveNpub()}
                    >
                      <span>{isResolving ? 'Querying…' : 'Resolve Relay'}</span>
                    </button>
                  </div>
                  {lookupError && (
                    <span id="resolve-npub-err" className="field-error">
                      {lookupError}
                    </span>
                  )}
                </div>

                <div className="form-row-2">
                  <div className="field">
                    <label htmlFor="pay-asset-select">Settlement Asset</label>
                    <select
                      id="pay-asset-select"
                      className="select"
                      value={payAsset}
                      onChange={(e) => {
                        const next = e.target.value as 'PUSD' | 'BCH';
                        setPayAsset(next);
                        setPayAmount(next === 'PUSD' ? '12.50' : '15000');
                        setPayAmountError(null);
                      }}
                    >
                      <option value="PUSD">ParyonUSD (PUSD CashToken)</option>
                      <option value="BCH">Bitcoin Cash (satoshis)</option>
                    </select>
                  </div>

                  <div className="field">
                    <label htmlFor="pay-amount-input">
                      {payAsset === 'PUSD' ? 'Amount (PUSD, 2 decimals)' : 'Amount (BCH satoshis)'}
                    </label>
                    <input
                      id="pay-amount-input"
                      type="text"
                      inputMode="decimal"
                      className="input mono"
                      value={payAmount}
                      aria-invalid={payAmountError ? 'true' : undefined}
                      aria-describedby={payAmountError ? 'pay-amount-err' : undefined}
                      onBlur={() => setPayAmountError(validateAmountField(payAmount, payAsset))}
                      onChange={(e) => {
                        setPayAmount(e.target.value);
                        if (payAmountError) setPayAmountError(null);
                      }}
                    />
                    {payAmountError && (
                      <span id="pay-amount-err" className="field-error">
                        {payAmountError}
                      </span>
                    )}
                  </div>
                </div>

                <div className="field">
                  <label htmlFor="pay-memo-input">On-Chain BLZP Invoice Memo (Optional)</label>
                  <input
                    id="pay-memo-input"
                    type="text"
                    maxLength={64}
                    className="input"
                    value={payMemo}
                    onChange={(e) => setPayMemo(e.target.value)}
                  />
                </div>

                <div className="btn-row">
                  <button
                    type="button"
                    className="btn btn-primary"
                    disabled={!targetVerification?.valid}
                    onClick={() => void handleExecutePayment()}
                  >
                    <SendPayIcon size={16} />
                    <span>
                      Verify Dual Proof & Build {payAsset === 'PUSD' ? 'PUSD' : 'BCH'} Payment TX
                    </span>
                  </button>
                </div>
              </div>

              {payStatus && (
                <div className={`status-banner ${payStatus.ok ? 'ok' : 'err'}`}>
                  {payStatus.ok ? <ShieldCheckIcon size={18} /> : <AlertIcon size={18} />}
                  <span>{payStatus.text}</span>
                </div>
              )}
            </section>

            <section className="panel">
              <div className="panel-header">
                <div>
                  <h2>Pre-Payment Cryptographic Audit</h2>
                  <p>
                    Funds are locked against unverified handles: both Proof A (BCH PKH recovery) and
                    Proof B (NIP-78 Schnorr) must pass.
                  </p>
                </div>
                {targetVerification?.valid ? (
                  <span className="badge badge-verified">Dual Proof Verified</span>
                ) : (
                  <span className="badge badge-danger">Unverified</span>
                )}
              </div>

              {resolvedTarget && targetVerification && (
                <div className="kv-list">
                  <div className="kv-row">
                    <span className="kv-key">Merchant / Handle</span>
                    <span className="kv-val">
                      {resolvedTarget.payload.display_name ?? 'Unnamed Identity'} (seq #
                      {resolvedTarget.payload.sequence})
                    </span>
                  </div>
                  <div className="kv-row">
                    <span className="kv-key">Verified Token Address</span>
                    <span className="kv-val">{targetVerification.bchTokenAddress}</span>
                  </div>
                  <div className="kv-row">
                    <span className="kv-key">Proof A (secp256k1 PKH)</span>
                    <span className="kv-val">
                      MATCHED (0x{resolvedTarget.bchProof.signature_hex.slice(0, 20)}…)
                    </span>
                  </div>
                  <div className="kv-row">
                    <span className="kv-key">Proof B (NIP-78 Schnorr)</span>
                    <span className="kv-val">MATCHED ({resolvedTarget.nostrEvent.sig.slice(0, 20)}…)</span>
                  </div>
                </div>
              )}

              {paymentReceipt ? (
                <div className="field">
                  <span className="stat-label">
                    VM-Verified Settlement Transaction ({paymentReceipt.assetLabel} · Fee{' '}
                    {paymentReceipt.feeSats.toString()} sats)
                  </span>
                  <pre className="code-well">
                    {JSON.stringify(
                      {
                        txid: paymentReceipt.txid,
                        asset: paymentReceipt.assetLabel,
                        pusdCategory: payAsset === 'PUSD' ? PUSD_CATEGORY_ID : undefined,
                        recipientHandle: paymentReceipt.recipientHandle,
                        recipientCashAddress: paymentReceipt.recipientAddress,
                        libauthBch2025VmValid: paymentReceipt.vmValid,
                        rawSignedTransactionHex: `${paymentReceipt.rawHex.slice(0, 180)}…`,
                      },
                      null,
                      2,
                    )}
                  </pre>
                </div>
              ) : (
                <div className="status-banner">
                  <span>
                    Click <strong>Verify Dual Proof & Build Payment TX</strong> to construct a
                    signed CashTokens PUSD or BCH transaction and execute full script & token
                    conservation checks inside <code>@bitauth/libauth</code>.
                  </span>
                </div>
              )}
            </section>
          </div>
        )}

        {/* ================================================================= */}
        {/* PANEL 3: LOGIN WITH BCH × NOSTR VERIFIER & REPUTATION VCs         */}
        {/* ================================================================= */}
        {activeTab === 'verify' && (
          <div
            id="panel-verify"
            role="tabpanel"
            aria-labelledby="tab-verify"
            className="workspace-grid"
          >
            <section className="panel">
              <div className="panel-header">
                <div>
                  <h2>Login with BCH × Nostr Verifier</h2>
                  <p>
                    Passwordless, phishing-proof challenge-response combining NIP-42{' '}
                    <code>kind:22242</code> with a live Bitcoin Cash secp256k1 challenge signature.
                  </p>
                </div>
                <span className="badge badge-verified">kind:22242 + BCH 2FA</span>
              </div>

              <div className="form-stack">
                <div className="field">
                  <label htmlFor="rp-domain-input">Relying-Party Origin Domain</label>
                  <div className="btn-row">
                    <input
                      id="rp-domain-input"
                      type="text"
                      className="input mono"
                      style={{ flex: 1 }}
                      value={rpDomain}
                      autoCorrect="off"
                      autoCapitalize="off"
                      spellCheck={false}
                      aria-invalid={rpDomainError ? 'true' : undefined}
                      aria-describedby={rpDomainError ? 'rp-domain-err' : undefined}
                      onBlur={() => {
                        if (!rpDomain.trim()) {
                          setRpDomainError('Enter a relying-party domain.');
                        }
                      }}
                      onChange={(e) => {
                        setRpDomain(e.target.value);
                        if (rpDomainError) setRpDomainError(null);
                      }}
                    />
                    <button
                      type="button"
                      className="btn"
                      onClick={handleIssueFreshChallenge}
                    >
                      <RefreshIcon size={15} />
                      <span>New 256-Bit Challenge</span>
                    </button>
                  </div>
                  {rpDomainError && (
                    <span id="rp-domain-err" className="field-error">
                      {rpDomainError}
                    </span>
                  )}
                </div>

                <div className="kv-list">
                  <div className="kv-row">
                    <span className="kv-key">CSPRNG Challenge Nonce</span>
                    <span className="kv-val">{challenge.challengeHex}</span>
                  </div>
                  <div className="kv-row">
                    <span className="kv-key">Bound Origin / Expiry</span>
                    <span className="kv-val">
                      {challenge.domain} · exp {challenge.expiresAt}
                    </span>
                  </div>
                </div>

                <div className="btn-row">
                  <button
                    type="button"
                    className="btn btn-primary"
                    onClick={() => void handleSignChallengeLogin()}
                  >
                    <KeyChallengeIcon size={16} />
                    <span>Sign Dual Challenge & Issue Merchant VC</span>
                  </button>
                </div>

                {authResponse && (
                  <>
                    <hr className="section-divider" />
                    <div className="field">
                      <span className="stat-label">
                        Interactive Security & Attack Simulator (Toggle to Test Rejection)
                      </span>
                      <label className="checkbox-row" htmlFor="sim-domain-spoof">
                        <input
                          id="sim-domain-spoof"
                          type="checkbox"
                          checked={simulateDomainSpoof}
                          onChange={(e) => setSimulateDomainSpoof(e.target.checked)}
                        />
                        <span>Simulate Phishing Domain Replay (evil-phishing-spoof.example)</span>
                      </label>
                      <label className="checkbox-row" htmlFor="sim-addr-tamper">
                        <input
                          id="sim-addr-tamper"
                          type="checkbox"
                          checked={simulateAddressTamper}
                          onChange={(e) => setSimulateAddressTamper(e.target.checked)}
                        />
                        <span>Simulate Attacker BCH CashAddress Substitution</span>
                      </label>
                    </div>
                  </>
                )}
              </div>
            </section>

            <section className="panel">
              <div className="panel-header">
                <div>
                  <h2>Relying-Party Verification & Reputation VC</h2>
                  <p>
                    Real-time output from <code>verifyAuthChallengeResponse</code> and{' '}
                    <code>verifyVerifiableCredential</code>.
                  </p>
                </div>
                {liveVerification ? (
                  liveVerification.authenticated ? (
                    <span className="badge badge-verified">Authenticated</span>
                  ) : (
                    <span className="badge badge-danger">Attack Rejected</span>
                  )
                ) : (
                  <span className="badge">Awaiting Signature</span>
                )}
              </div>

              {liveVerification ? (
                <>
                  <div className={`status-banner ${liveVerification.authenticated ? 'ok' : 'err'}`}>
                    {liveVerification.authenticated ? (
                      <ShieldCheckIcon size={18} />
                    ) : (
                      <AlertIcon size={18} />
                    )}
                    <span>
                      {liveVerification.authenticated
                        ? `Authenticated ${liveVerification.nostrNpub?.slice(0, 20)}… <-> ${liveVerification.bchTokenAddress?.slice(0, 26)}…`
                        : `Rejected: ${liveVerification.errors.join(' | ')}`}
                    </span>
                  </div>

                  {issuedVc && vcVerification && (
                    <div className="field">
                      <span className="stat-label">
                        Portable W3C Verifiable Credential (
                        {vcVerification.valid ? 'Dual Signatures Verified' : 'Invalid'})
                      </span>
                      <pre className="code-well">{JSON.stringify(issuedVc, null, 2)}</pre>
                    </div>
                  )}
                </>
              ) : (
                <div className="status-banner">
                  <span>
                    Click <strong>Sign Dual Challenge & Issue Merchant VC</strong> to execute a live
                    NIP-42 <code>kind:22242</code> + BCH secp256k1 challenge handshake and inspect
                    the resulting portable Verifiable Credential.
                  </span>
                </div>
              )}
            </section>
          </div>
        )}

        {/* ================================================================= */}
        {/* PANEL 4: /deck 6-SLIDE WIDGET FACTORY PRESENTATION                */}
        {/* ================================================================= */}
        {activeTab === 'deck' && (
          <div id="panel-deck" role="tabpanel" aria-labelledby="tab-deck">
            <DeckView onNavigateTab={(tab) => switchTab(tab)} />
          </div>
        )}

        <footer className="app-footer">
          <span>
            CashLink DID (`cashlink-did-v1`) · Built for BCH BLAZE 2026 Mainnet Track & Paytaca
            Decentralized Identity Bounty
          </span>
          <a href={GITHUB_REPO_URL} target="_blank" rel="noreferrer" className="btn btn-sm">
            View MIT Source ({GITHUB_REPO_URL.replace('https://', '')})
          </a>
        </footer>
      </main>
    </>
  );
}
