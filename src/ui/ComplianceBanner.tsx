import React, { useEffect, useRef, useState } from 'react';
import { AlphanumericQRCode, type UseWizardConnectResult } from '@wizardconnect/react';
import {
  type BchNetworkId,
  EMBER2026_VOTING_TOKEN_ADDRESS,
  GITHUB_REPO_URL,
} from '../sdk/index.js';
import {
  CheckIcon,
  CopyIcon,
  GithubIcon,
  SlidesIcon,
  WalletIcon,
} from './Icons.js';

export interface ComplianceBannerProps {
  network: BchNetworkId;
  onChangeNetwork: (next: BchNetworkId) => void;
  onOpenDeck: () => void;
  isDeckActive: boolean;
  wizard: UseWizardConnectResult;
  connectedBchAddress: string | null;
}

export function ComplianceBanner({
  network,
  onChangeNetwork,
  onOpenDeck,
  isDeckActive,
  wizard,
  connectedBchAddress,
}: ComplianceBannerProps): React.ReactElement {
  const [copiedEmber, setCopiedEmber] = useState(false);
  const [copiedWcUri, setCopiedWcUri] = useState(false);
  const [modalOpen, setModalOpen] = useState(false);
  const dialogRef = useRef<HTMLDialogElement | null>(null);

  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;
    if (modalOpen && !dialog.open) {
      dialog.showModal();
    } else if (!modalOpen && dialog.open) {
      dialog.close();
    }
  }, [modalOpen]);

  useEffect(() => {
    if (wizard.state === 'connected' && modalOpen) {
      setModalOpen(false);
    }
  }, [wizard.state, modalOpen]);

  const handleCopyEmber = async () => {
    try {
      await navigator.clipboard.writeText(EMBER2026_VOTING_TOKEN_ADDRESS);
      setCopiedEmber(true);
      setTimeout(() => setCopiedEmber(false), 1800);
    } catch {
      // Clipboard API fallback ignored in headless tests
    }
  };

  const handleOpenWizardModal = () => {
    if (wizard.state === 'idle' || wizard.state === 'disconnected') {
      wizard.connect();
    }
    setModalOpen(true);
  };

  const handleCopyWcUri = async () => {
    if (!wizard.uri) return;
    try {
      await navigator.clipboard.writeText(wizard.uri);
      setCopiedWcUri(true);
      setTimeout(() => setCopiedWcUri(false), 1800);
    } catch {
      // Clipboard API fallback ignored
    }
  };

  const shortEmber = `${EMBER2026_VOTING_TOKEN_ADDRESS.slice(0, 18)}…${EMBER2026_VOTING_TOKEN_ADDRESS.slice(-8)}`;

  return (
    <>
      <header className="compliance-bar">
        <div className="compliance-inner">
          <nav className="compliance-group" aria-label="BCH BLAZE 2026 Hackathon Compliance Links">
            <a
              href="#/deck"
              onClick={(e) => {
                e.preventDefault();
                onOpenDeck();
              }}
              className={`btn btn-sm ${isDeckActive ? 'btn-primary' : ''}`}
            >
              <SlidesIcon size={15} />
              <span>/deck Presentation</span>
            </a>

            <a
              href={GITHUB_REPO_URL}
              target="_blank"
              rel="noreferrer"
              className="btn btn-sm"
            >
              <GithubIcon size={15} />
              <span>LBCron/bch-nostr-idpay</span>
            </a>

            <div className="ember-pill" title={EMBER2026_VOTING_TOKEN_ADDRESS}>
              <strong>EMBER2026 Vote:</strong>
              <code className="mono">{shortEmber}</code>
              <button
                type="button"
                className="btn btn-sm"
                onClick={handleCopyEmber}
                aria-label="Copy EMBER2026 CashTokens voting address"
              >
                {copiedEmber ? <CheckIcon size={14} /> : <CopyIcon size={14} />}
                <span>{copiedEmber ? 'Copied' : 'Copy'}</span>
              </button>
            </div>
          </nav>

          <div className="compliance-group">
            <div className="btn-row" role="group" aria-label="Bitcoin Cash Network Selector">
              <button
                type="button"
                className={`btn btn-sm ${network === 'mainnet' ? 'btn-primary' : ''}`}
                onClick={() => onChangeNetwork('mainnet')}
                aria-pressed={network === 'mainnet'}
              >
                BCH Mainnet
              </button>
              <button
                type="button"
                className={`btn btn-sm ${network === 'chipnet' ? 'btn-primary' : ''}`}
                onClick={() => onChangeNetwork('chipnet')}
                aria-pressed={network === 'chipnet'}
              >
                Chipnet
              </button>
            </div>

            {wizard.state === 'connected' ? (
              <button
                type="button"
                className="btn btn-sm"
                onClick={() => void wizard.disconnect()}
                title={connectedBchAddress ?? undefined}
              >
                <WalletIcon size={15} />
                <span>
                  {wizard.walletName ?? 'Wallet'}:{' '}
                  {connectedBchAddress ? `${connectedBchAddress.slice(12, 20)}…` : 'Connected'}
                </span>
              </button>
            ) : (
              <button
                type="button"
                className="btn btn-sm btn-primary"
                onClick={handleOpenWizardModal}
              >
                <WalletIcon size={15} />
                <span>WizardConnect</span>
              </button>
            )}
          </div>
        </div>
      </header>

      <dialog
        ref={dialogRef}
        className="wc-dialog"
        aria-labelledby="wc-modal-title"
        onClose={() => setModalOpen(false)}
        onClick={(e) => {
          if (e.target === dialogRef.current) {
            setModalOpen(false);
          }
        }}
      >
        <div className="wc-dialog-body">
          <div className="panel-header">
            <div>
              <h2 id="wc-modal-title">Connect BCH Wallet via WizardConnect</h2>
              <p>
                Scan with a WizardConnect-enabled Bitcoin Cash HD wallet over encrypted NIP-59 Nostr
                relays (`wss://relay.riften.net:443`).
              </p>
            </div>
            <button
              type="button"
              className="btn btn-sm"
              onClick={() => setModalOpen(false)}
            >
              Close
            </button>
          </div>

          {wizard.qrUri ? (
            <div className="qr-frame">
              <AlphanumericQRCode
                value={wizard.qrUri}
                size={240}
                foreground="#06140f"
                background="#ffffff"
              />
            </div>
          ) : (
            <div className="status-banner">
              <span>Generating encrypted NIP-59 session URI (`wiz://`)…</span>
            </div>
          )}

          {wizard.uri && (
            <div className="field">
              <label htmlFor="wc-pairing-uri">WizardConnect Pairing URI</label>
              <div className="btn-row">
                <input
                  id="wc-pairing-uri"
                  type="text"
                  readOnly
                  value={wizard.uri}
                  className="input mono"
                  autoCorrect="off"
                  autoCapitalize="off"
                  spellCheck={false}
                />
                <button type="button" className="btn" onClick={handleCopyWcUri}>
                  {copiedWcUri ? <CheckIcon size={15} /> : <CopyIcon size={15} />}
                  <span>{copiedWcUri ? 'Copied URI' : 'Copy wiz:// URI'}</span>
                </button>
              </div>
              <span className="field-hint">
                No mobile wallet handy? Every tab also includes an instant client-side non-custodial
                sandbox signer verified inside `@bitauth/libauth`’s BCH 2025 Virtual Machine.
              </span>
            </div>
          )}

          {wizard.error && (
            <div className="status-banner err">
              <span>{wizard.error}</span>
            </div>
          )}
        </div>
      </dialog>
    </>
  );
}
