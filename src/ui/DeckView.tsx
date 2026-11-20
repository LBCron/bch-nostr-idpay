import React, { useEffect, useState } from 'react';
import {
  EMBER2026_VOTING_TOKEN_ADDRESS,
  GITHUB_REPO_URL,
  PUSD_CATEGORY_ID,
} from '../sdk/index.js';
import { ShieldCheckIcon } from './Icons.js';

export interface DeckViewProps {
  onNavigateTab: (tab: 'bind' | 'pay' | 'verify') => void;
}

interface SlideSpec {
  stepNumber: number;
  stepName: string;
  title: string;
  lead: string;
  bullets: string[];
  technicalCardTitle: string;
  technicalRows: Array<{ label: string; value: string }>;
}

const SLIDES: SlideSpec[] = [
  {
    stepNumber: 1,
    stepName: 'Title & Team',
    title: 'CashLink DID — Decentralized BCH × Nostr Identity & ParyonUSD Payments',
    lead: 'Self-sovereign human handles, phishing-proof Web3 login, and instant ParyonUSD (PUSD) CashToken settlements on Bitcoin Cash Mainnet — with zero centralized servers.',
    bullets: [
      'Repository: github.com/LBCron/bch-nostr-idpay (MIT Open Source)',
      'Tracks: BCH BLAZE 2026 Mainnet Track + Paytaca Decentralized Identity Bounty',
      'Builder: @LBCron — Full-Stack Bitcoin Cash Covenant, Libauth & Nostr Protocol Engineering',
    ],
    technicalCardTitle: 'Submission Coordinates',
    technicalRows: [
      { label: 'Protocol Spec', value: 'cashlink-did-v1 (NIP-78 + NIP-42 + CashTokens)' },
      { label: 'Mainnet Token', value: `ParyonUSD (${PUSD_CATEGORY_ID.slice(0, 16)}…)` },
      { label: 'GitHub Repo', value: GITHUB_REPO_URL.replace('https://', '') },
      { label: 'EMBER2026 Vote', value: `${EMBER2026_VOTING_TOKEN_ADDRESS.slice(0, 24)}…` },
    ],
  },
  {
    stepNumber: 2,
    stepName: 'The Story',
    title: 'Why Peer-to-Peer Electronic Cash Needs Decentralized Human Identity',
    lead: 'Sending money globally on Bitcoin Cash costs less than $0.002, yet everyday commerce still stumbles on 54-character CashAddresses and DNS-controlled handle directories.',
    bullets: [
      'Raw bitcoincash:z... strings are error-prone and give payers zero proof of who owns the receiving address.',
      'Legacy handle services rely on centralized SQL databases or custodial servers that can censor, expire, or silently swap addresses.',
      'Reusing a single private key across social messaging and on-chain funds exposes high-value BCH & PUSD balances to hot-key leakage.',
    ],
    technicalCardTitle: 'Failure Modes Eliminated',
    technicalRows: [
      { label: 'Centralized Handle DB', value: 'Replaced by signed NIP-78 Nostr events' },
      { label: 'Hot-Key Reuse Risk', value: 'Strict BCH ≠ Nostr key separation enforced' },
      { label: 'Clipboard Hijacking', value: 'Dual secp256k1 + Schnorr proof verified pre-pay' },
      { label: 'OAuth Lock-In', value: 'Replaced by kind:22242 + BCH challenge login' },
    ],
  },
  {
    stepNumber: 3,
    stepName: 'Benefits',
    title: 'Send PUSD to Any @npub and Authenticate Without Passwords',
    lead: 'CashLink DID turns every Nostr identity into a cryptographically verified Bitcoin Cash & CashTokens payment endpoint and portable reputation credential.',
    bullets: [
      'Zero-Database Discovery: Resolve any npub1... across public Nostr relays and verify both signatures client-side before a single satoshi moves.',
      'Native Stablecoin Commerce: Pay verified merchants in ParyonUSD (PUSD, 2 decimals) or BCH with on-chain BLZP invoice memos.',
      'Phishing-Proof Authentication: "Login with BCH×Nostr" binds challenge nonces to the exact relying-party domain and live keys.',
    ],
    technicalCardTitle: 'Dual Proof Guarantee',
    technicalRows: [
      { label: 'Proof A (BCH Key)', value: 'Compact secp256k1 signature -> PKH recovery' },
      { label: 'Proof B (Nostr Key)', value: 'BIP-340 Schnorr signature on kind:30078' },
      { label: 'Relying Party Auth', value: 'NIP-42 kind:22242 + live BCH challenge sig' },
      { label: 'Merchant Trust', value: 'Portable W3C Verifiable Credentials' },
    ],
  },
  {
    stepNumber: 4,
    stepName: 'BCH Usage',
    title: 'Deep Bitcoin Cash Mainnet Stack: Covenants, CashTokens & WizardConnect',
    lead: 'Every layer uses real, consensus-verified Bitcoin Cash primitives — compiled with CashScript 0.14.0 and verified in @bitauth/libauth’s BCH 2025 Virtual Machine.',
    bullets: [
      'IdentityAnchor.cash Covenant: CashScript 0.14.0 contract enforcing owner-signed key rotation, guardian recovery, and BLZR NFT burn revocation on 40-byte mutable NFT commitments.',
      'On-Chain Anchors & PUSD Settlement: OP_RETURN "BLZI" + sha256(payload) commitments and real CashTokens PUSD (2469acc5...) UTXO construction.',
      'WizardConnect NIP-59 Integration: Zero-round-trip BIP32 xpub address derivation and encrypted remote wallet signing.',
    ],
    technicalCardTitle: 'On-Chain Primitives',
    technicalRows: [
      { label: 'Smart Contract', value: 'contracts/IdentityAnchor.cash (P2SH32)' },
      { label: 'NFT Commitment', value: 'sha256(nostrPub32 || pkh20) || seq_le64 (40 B)' },
      { label: 'Anchor / Pay Prefixes', value: '0x424c5a49 ("BLZI") / 0x424c5a50 ("BLZP")' },
      { label: 'Wallet Transport', value: 'WizardConnect over wss://relay.riften.net:443' },
    ],
  },
  {
    stepNumber: 5,
    stepName: 'The Vision',
    title: 'Open Identity Rail for Paytaca, Selene & Global BCH Commerce',
    lead: 'CashLink DID is architected as a lightweight, MIT-licensed TypeScript SDK that any Bitcoin Cash wallet, POS terminal, or web app can embed in minutes.',
    bullets: [
      'Wallet-Native @npub Resolution: Drop-in SDK for Paytaca and Selene so users type a Nostr handle and pay PUSD with cryptographic certainty.',
      'Decentralized Merchant Directories: Portable Verifiable Credentials enable community-curated merchant reputation without platform gatekeepers.',
      'Hardware Guardian Recovery: Rotate compromised hot social keys on-chain via IdentityAnchor.cash without losing merchant reputation.',
    ],
    technicalCardTitle: 'Post-BLAZE Roadmap',
    technicalRows: [
      { label: 'Phase 1 (Live Today)', value: 'SDK + CashScript Covenant + PUSD Web App' },
      { label: 'Phase 2 (Q4 2026)', value: 'NIP-05 human alias bridge & POS QR mode' },
      { label: 'Phase 3 (Q1 2027)', value: 'Chaingraph indexer for covenant rotations' },
      { label: 'License', value: '100% Open Source MIT' },
    ],
  },
  {
    stepNumber: 6,
    stepName: 'Thank You',
    title: 'Test CashLink DID Live Right Now in Your Browser',
    lead: 'Every flow in this app executes real secp256k1, BIP-340 Schnorr, CashScript 0.14.0 covenant logic, and @bitauth/libauth BCH 2025 VM verification.',
    bullets: [
      'Step 1: Open "Bind & Anchor" to sign a dual BCH × Nostr proof and build a real BLZI + Identity NFT transaction.',
      'Step 2: Open "Resolve & Pay PUSD" to verify a merchant npub and execute a VM-verified ParyonUSD CashToken transfer.',
      'Step 3: Open "Login Verifier" to test live kind:22242 challenge-response and watch tampered proofs fail instantly.',
    ],
    technicalCardTitle: 'Support CashLink DID',
    technicalRows: [
      { label: 'Community Vote Token', value: 'EMBER2026 CashTokens' },
      { label: 'Voting CashAddress', value: EMBER2026_VOTING_TOKEN_ADDRESS },
      { label: 'Test Suite', value: 'npm test (Vitest + Local WS Nostr Relay)' },
      { label: 'Source Code', value: GITHUB_REPO_URL },
    ],
  },
];

export function DeckView({ onNavigateTab }: DeckViewProps): React.ReactElement {
  const [index, setIndex] = useState(0);
  const slide = SLIDES[index];

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'ArrowRight') {
        setIndex((prev) => Math.min(SLIDES.length - 1, prev + 1));
      } else if (e.key === 'ArrowLeft') {
        setIndex((prev) => Math.max(0, prev - 1));
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, []);

  return (
    <section className="deck-stage" aria-label="BCH BLAZE 2026 6-Slide Interactive Presentation">
      <div className="deck-top">
        <span className="badge badge-verified">
          Slide {slide.stepNumber} of {SLIDES.length} · {slide.stepName}
        </span>

        <div className="deck-dots" role="group" aria-label="Presentation Slide Selector">
          {SLIDES.map((s, idx) => (
            <button
              key={s.stepNumber}
              type="button"
              className="deck-dot"
              aria-current={idx === index ? 'step' : undefined}
              onClick={() => setIndex(idx)}
              title={`Slide ${s.stepNumber}: ${s.stepName}`}
            >
              {s.stepNumber}
            </button>
          ))}
        </div>
      </div>

      <div className="deck-body">
        <div>
          <h2 className="deck-slide-title">{slide.title}</h2>
          <p>{slide.lead}</p>
          <ul className="deck-points">
            {slide.bullets.map((b) => (
              <li key={b}>
                <ShieldCheckIcon size={18} />
                <span>{b}</span>
              </li>
            ))}
          </ul>
        </div>

        <div className="code-well" style={{ maxHeight: 'none', padding: '20px' }}>
          <h3 style={{ fontSize: '0.95rem', marginBottom: '12px' }}>{slide.technicalCardTitle}</h3>
          <div className="kv-list">
            {slide.technicalRows.map((row) => (
              <div key={row.label} className="kv-row">
                <span className="kv-key">{row.label}</span>
                <span className="kv-val">{row.value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="deck-footer">
        <div className="btn-row">
          <button
            type="button"
            className="btn"
            disabled={index === 0}
            onClick={() => setIndex((prev) => Math.max(0, prev - 1))}
          >
            Previous Slide
          </button>
          <button
            type="button"
            className="btn btn-primary"
            disabled={index === SLIDES.length - 1}
            onClick={() => setIndex((prev) => Math.min(SLIDES.length - 1, prev + 1))}
          >
            Next Slide
          </button>
        </div>

        <div className="btn-row">
          <button type="button" className="btn" onClick={() => onNavigateTab('bind')}>
            Try Identity Anchor
          </button>
          <button type="button" className="btn" onClick={() => onNavigateTab('pay')}>
            Try PUSD Payment
          </button>
          <button type="button" className="btn" onClick={() => onNavigateTab('verify')}>
            Try Login Verifier
          </button>
        </div>
      </div>
    </section>
  );
}
