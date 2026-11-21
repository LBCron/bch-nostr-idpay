export type BchNetworkId = 'mainnet' | 'chipnet' | 'mocknet';

/**
 * Official ParyonUSD (`PUSD`) CashToken Category ID on Bitcoin Cash Mainnet
 * Verified from https://paryonusd.com/#token-id & https://bcmr.paytaca.com/api/tokens/2469acc5.../
 */
export const PUSD_CATEGORY_ID =
  '2469acc5afa4b10cb5b5c04afb89c3a3ffd61c5da9c01e26d00951cae2a02544';

/**
 * Official BCMR decimal places for ParyonUSD (`PUSD`): 2 decimals (1.00 PUSD = 100 base units)
 */
export const PUSD_DECIMALS = 2;

export const PAYTACA_BCMR_PUSD_URL = `https://bcmr.paytaca.com/api/tokens/${PUSD_CATEGORY_ID}/`;

/**
 * On-chain OP_RETURN 4-byte protocol prefixes:
 * - "BLZI" (0x424c5a49): CashLink DID Identity Anchor commitment
 * - "BLZR" (0x424c5a52): CashLink DID Identity Revocation marker
 * - "BLZP" (0x424c5a50): CashLink DID Identity Payment memo/receipt
 */
export const BLAZE_ANCHOR_PREFIX_UTF8 = 'BLZI';
export const BLAZE_ANCHOR_PREFIX_HEX = '424c5a49';
export const BLAZE_REVOKE_PREFIX_HEX = '424c5a52';
export const BLAZE_PAY_PREFIX_HEX = '424c5a50';

/**
 * Nostr Event Kinds:
 * - 30078 (NIP-78): Parameterized replaceable application-specific data (Identity Binding & Verifiable Credentials)
 * - 22242 (NIP-42): Ephemeral client authentication challenge-response ("Login with BCH×Nostr")
 */
export const NOSTR_KIND_IDENTITY_BINDING = 30078;
export const NOSTR_BINDING_D_TAG = 'bch-nostr-idpay:v1';
export const NOSTR_VC_D_TAG_PREFIX = 'bch-nostr-vc:v1:';
export const NOSTR_KIND_AUTH_CHALLENGE = 22242;

/**
 * Live Bitcoin Cash & Nostr Infrastructure Endpoints
 */
export const ELECTRUM_ENDPOINTS: Record<'mainnet' | 'chipnet', string[]> = {
  mainnet: [
    'wss://electrum.imaginary.cash:50004',
    'wss://bch.imaginary.cash:50004',
  ],
  chipnet: ['wss://chipnet.imaginary.cash:50004'],
};

export const EXPLORER_TX_BASE_URL: Record<BchNetworkId, string> = {
  mainnet: 'https://explorer.salemkode.com/tx/',
  chipnet: 'https://chipnet.chaingraph.cash/tx/',
  mocknet: 'https://explorer.salemkode.com/tx/',
};

export const CHAINGRAPH_GRAPHQL_URL = 'https://gql.chaingraph.pat.mn/v1/graphql';

export const WIZARDCONNECT_RELAY_URLS = [
  'wss://relay.riften.net:443',
  'wss://relay.cauldron.quest:443',
];

export const DEFAULT_NOSTR_DISCOVERY_RELAYS = [
  'wss://relay.damus.io',
  'wss://nos.lol',
  'wss://relay.primal.net',
];

export const DEFAULT_NOSTR_RELAYS = DEFAULT_NOSTR_DISCOVERY_RELAYS;

/**
 * Official GitHub Repository & Project Metadata for BCH BLAZE 2026 Compliance Banner
 */
export const PROJECT_METADATA = {
  name: 'CashLink DID',
  tagline: 'Self-Sovereign BCH × Nostr Identity, CashScript Covenant & Instant PUSD Payments',
  repoUrl: 'https://github.com/LBCron/bch-nostr-idpay',
  liveDemoUrl: 'https://lbcron.github.io/bch-nostr-idpay/',
  hackathonName: 'BCH BLAZE 2026',
  builderHandle: '@LBCron',
} as const;

export const GITHUB_REPO_URL = PROJECT_METADATA.repoUrl;

/**
 * Canonical CashTokens-capable `bitcoincash:z...` address for EMBER2026 Community Choice voting & PUSD rewards (@LBCron)
 */
export const EMBER2026_VOTING_TOKEN_ADDRESS =
  'bitcoincash:zrmzsnappljxj2p7lukt7vaukjg08xysusdswzruk0';

export const DUST_SATOSHIS = 1000n;
export const TOKEN_DUST_SATOSHIS = 1000n;
