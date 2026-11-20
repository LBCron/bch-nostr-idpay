import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { App } from '../src/ui/App.js';
import { DeckView } from '../src/ui/DeckView.js';
import { EMBER2026_VOTING_TOKEN_ADDRESS, GITHUB_REPO_URL, PUSD_CATEGORY_ID } from '../src/sdk/index.js';

describe('CashLink DID — High-Craft Web UI & Mandatory BCH BLAZE Compliance Render Suite', () => {
  it('renders App with mandatory top compliance banner (/deck, GitHub repo, EMBER2026 vote, PUSD & Covenant metrics)', () => {
    const html = renderToStaticMarkup(<App />);
    expect(html).toContain('/deck Presentation');
    expect(html).toContain(GITHUB_REPO_URL);
    expect(html).toContain(EMBER2026_VOTING_TOKEN_ADDRESS.slice(0, 18));
    expect(html).toContain(PUSD_CATEGORY_ID.slice(0, 12));
    expect(html).toContain('IdentityAnchor');
    expect(html).toContain('Skip to main content');
    expect(html).toContain('1. Bind &amp; Anchor Identity');
    expect(html).toContain('2. Resolve @npub &amp; Pay PUSD');
    expect(html).toContain('3. Login Verifier &amp; VCs');
    expect(html).toContain('4. Pitch Deck (/deck)');
  });

  it('renders 6-Slide Widget Factory Presentation Deck cleanly', () => {
    const html = renderToStaticMarkup(<DeckView onNavigateTab={() => undefined} />);
    expect(html).toContain('Slide 1 of 6');
    expect(html).toContain('Title &amp; Team');
    expect(html).toContain('CashLink DID');
    expect(html).toContain('ParyonUSD');
  });
});
