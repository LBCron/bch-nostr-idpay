# CashLink DID (`bch-nostr-idpay`)

**Self-Sovereign Bitcoin Cash × Nostr Decentralized Identity, CashScript `0.14.0` Key-Rotation Covenants, and Instant ParyonUSD (`PUSD`) CashToken Settlements.**

Built for **BCH BLAZE 2026** (**Mainnet Track** + **Paytaca Decentralized Identity Bounty**).

---

## Overview

Peer-to-peer electronic cash on Bitcoin Cash settles globally for `< $0.002`, yet everyday commerce still forces users to copy-paste raw `54`-character `bitcoincash:z...` strings or trust centralized DNS/SQL handle directories that can censor, expire, or swap addresses.

**CashLink DID (`cashlink-did:v1`)** bridges **Bitcoin Cash Mainnet + CashTokens** with **Nostr** (`NIP-78` + `NIP-42` + `NIP-59` WizardConnect) using **100% client-side, zero-server cryptography**:

1. **Non-Custodial Dual Cryptographic Identity Binding (`src/sdk/identity.ts`)**:
   - Strict zero-key-reuse enforcement (`assertDistinctKeyMaterial`): your Bitcoin Cash `secp256k1` spending key and Nostr `BIP-340` Schnorr social key never share secret material.
   - **Proof A (BCH Key Ownership)**: Bitcoin Cash Signed Message compact/Schnorr `secp256k1` signature verified directly against the user's `20`-byte `HASH160` CashAddress payload (`bitcoincash:q...` and CashTokens-aware `bitcoincash:z...`).
   - **Proof B (Nostr Key Ownership)**: Signed `NIP-78` (`kind: 30078`, `["d", "bch-nostr-idpay:v1"]`) parameterized replaceable attestation over the canonical JSON binding payload.
2. **CashScript `0.14.0` Identity Covenant (`contracts/IdentityAnchor.cash`)**:
   - P2SH32 covenant locking a mutable CashTokens Identity NFT (`40`-byte commitment: `sha256(nostrPubkey32 || ownerPkh20) || toPaddedBytes(sequence, 8)`).
   - Enforces authorized `rotateIdentity` (`sequence + 1`), hardware/social guardian `recoverIdentity`, and permanent `revokeIdentity` (`0x6a04424c5a5220` `"BLZR"` `OP_RETURN` + NFT burn).
3. **ParyonUSD (`PUSD`) & `BLZI` On-Chain Settlement (`src/sdk/transactions.ts`)**:
   - Constructs real `"BLZI"` (`0x424c5a49`) `OP_RETURN` anchor transactions and **ParyonUSD (`PUSD`)** CashToken transfers (`2469acc5afa4b10cb5b5c04afb89c3a3ffd61c5da9c01e26d00951cae2a02544`, `2` decimals per official Paytaca BCMR) with mandatory pre-payment dual proof verification and `@bitauth/libauth` **BCH 2025 Virtual Machine** script/token validation.
4. **WizardConnect NIP-59 Wallet Integration (`src/sdk/wizardconnect.ts`)**:
   - Zero-round-trip `BIP32` `xpub` CashAddress derivation and remote transaction signing over encrypted `NIP-59` gift-wrapped Nostr relays (`wss://relay.riften.net:443`).
5. **Phishing-Proof `"Login with BCH×Nostr"` & Portable Reputation VCs (`src/sdk/verifier.ts`)**:
   - `256`-bit CSPRNG challenge bound to the relying-party origin domain, verified via `NIP-42` `kind: 22242` + live BCH `secp256k1` second-factor challenge signature, plus W3C-compatible Verifiable Credentials (`VerifiedPusdMerchant`).

---

## Repository Structure

```text
bch-nostr-idpay/
├── contracts/
│   └── IdentityAnchor.cash             # CashScript 0.14.0 mutable Identity NFT covenant
├── src/
│   ├── contracts/
│   │   └── IdentityAnchor.artifact.json # Compiled cashc 0.14.0 P2SH32 artifact
│   ├── sdk/
│   │   ├── constants.ts                # Mainnet PUSD category, BCMR decimals (2), Electrum & relay URLs
│   │   ├── identity.ts                 # Dual BCH × Nostr proof creation, verification & W3C VCs
│   │   ├── verifier.ts                 # NIP-42 kind:22242 + BCH challenge-response verifier
│   │   ├── transactions.ts             # BLZI anchor & PUSD CashToken TX builder + libauth BCH 2025 VM check
│   │   ├── covenant.ts                 # IdentityAnchor.cash rotation, guardian recovery & revocation SDK
│   │   ├── discovery.ts                # Nostr SimplePool publish/resolve + ElectrumNetworkProvider helpers
│   │   ├── wizardconnect.ts            # WizardConnect NIP-59 BIP32 xpub & remote signing adapter
│   │   └── localRelay.ts               # Embedded WebSocket NIP-01/33/59 Nostr relay for deterministic E2E tests
│   └── ui/
│       ├── ComplianceBanner.tsx        # Mandatory BCH BLAZE top bar (/deck, GitHub, EMBER2026, WizardConnect)
│       ├── DeckView.tsx                # 6-Slide interactive "Widget Factory" presentation (/deck)
│       ├── App.tsx                     # 4-workspace web application (Bind, Pay PUSD, Login Verifier, Deck)
│       └── Icons.tsx                   # Crisp authored inline SVG icon system
└── test/
    ├── cashlink-did.test.ts            # 5 E2E suites: dual crypto, challenge auth, PUSD VM, covenant, WizardConnect
    └── ui-render.test.tsx              # Compliance banner & 6-slide /deck render verification
```

---

## Quick Start

```bash
# 1. Install dependencies
npm install

# 2. Compile IdentityAnchor.cash with cashc 0.14.0 and run full Vitest E2E suite
npm test

# 3. Build production web application into dist/
npm run build

# 4. Launch interactive local dev server
npm run dev
```

---

## License

MIT — see [LICENSE](./LICENSE).
