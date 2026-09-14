/* Procedural SVG: the key-separation payout path. No external assets.
 *
 *   Scanner ──signs──▶ Finding ──▶ Independent Verifier(s) ──▶ Treasury ──▶ payout
 *   (scanner key)      (signed)     (≥2 keys, 1 external)      (separate key)
 *
 * The point the diagram must make visually: the box that FINDS (red) and the box
 * that PAYS (gold) are different containers holding different keys, with two
 * independent verifiers wedged between them. MOMUS cannot pay itself.
 */
import { useI18n } from '../i18n';

export function KeySeparationDiagram() {
  const { t } = useI18n();
  return (
    <div className="diagram-scroll">
      <svg
        className="keysep"
        viewBox="0 0 940 260"
        role="img"
        aria-label={t(
          'keys.diagram_aria',
          undefined,
          'Key separation: Scanner signs a finding; independent verifiers confirm; a separate Treasury key releases the payout.',
        )}
      >
        <defs>
          <marker id="arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
            <path d="M0,0 L10,5 L0,10 z" fill="var(--wire)" />
          </marker>
          <linearGradient id="scannerFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stopColor="rgba(255,45,85,0.18)" />
            <stop offset="1" stopColor="rgba(255,45,85,0.05)" />
          </linearGradient>
          <linearGradient id="treasuryFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stopColor="rgba(255,204,51,0.20)" />
            <stop offset="1" stopColor="rgba(255,204,51,0.05)" />
          </linearGradient>
        </defs>

        {/* wires */}
        <g fill="none" stroke="var(--wire)" strokeWidth="1.6" markerEnd="url(#arrow)">
          <path d="M150,86 L214,86" />
          <path d="M330,86 L394,86" />
          <path d="M510,86 L574,86" />
          <path d="M690,86 L754,86" />
        </g>

        {/* Scanner (red) — holds only the scanner key */}
        <g>
          <rect x="20" y="46" width="130" height="80" rx="10" fill="url(#scannerFill)" stroke="var(--sev-critical)" strokeWidth="1.6" />
          <text x="85" y="78" className="k-title" fill="var(--sev-critical)">{t('keys.scanner_title', undefined, 'Scanner')}</text>
          <text x="85" y="98" className="k-sub">MOMUS</text>
          <text x="85" y="114" className="k-key">{t('keys.scanner_key_label', undefined, '🔑 scanner key')}</text>
        </g>

        {/* Finding (signed) */}
        <g>
          <rect x="214" y="52" width="116" height="68" rx="10" fill="rgba(255,255,255,0.04)" stroke="var(--wire-strong)" strokeWidth="1.4" />
          <text x="272" y="82" className="k-title">{t('keys.finding_title', undefined, 'Finding')}</text>
          <text x="272" y="102" className="k-sub">{t('keys.finding_signed', undefined, 'Ed25519-signed')}</text>
        </g>

        {/* Independent verifiers */}
        <g>
          <rect x="394" y="30" width="116" height="52" rx="10" fill="rgba(77,184,255,0.10)" stroke="var(--sev-low)" strokeWidth="1.4" />
          <text x="452" y="52" className="k-title" fill="var(--sev-low)">{t('keys.verifier_a_title', undefined, 'Verifier A')}</text>
          <text x="452" y="70" className="k-sub">{t('keys.verifier_a_source', undefined, 'Metis (external)')}</text>

          <rect x="394" y="90" width="116" height="52" rx="10" fill="rgba(77,184,255,0.10)" stroke="var(--sev-low)" strokeWidth="1.4" />
          <text x="452" y="112" className="k-title" fill="var(--sev-low)">{t('keys.verifier_b_title', undefined, 'Verifier B')}</text>
          <text x="452" y="130" className="k-sub">{t('keys.verifier_b_distinct_key', undefined, 'distinct key')}</text>

          <text x="452" y="164" className="k-note">{t('keys.verifier_quorum_note', undefined, '≥2 keys · high/critical')}</text>
        </g>

        {/* Treasury (gold) — separate key, separate container */}
        <g>
          <rect x="574" y="46" width="116" height="80" rx="10" fill="url(#treasuryFill)" stroke="var(--sev-medium)" strokeWidth="1.6" />
          <text x="632" y="78" className="k-title" fill="var(--sev-medium)">Treasury</text>
          <text x="632" y="98" className="k-sub">{t('keys.treasury_separate_container', undefined, 'separate container')}</text>
          <text x="632" y="114" className="k-key">{t('keys.treasury_key_label', undefined, '🔑 treasury key')}</text>
        </g>

        {/* Payout */}
        <g>
          <rect x="754" y="52" width="116" height="68" rx="10" fill="rgba(34,197,94,0.10)" stroke="#22c55e" strokeWidth="1.4" />
          <text x="812" y="82" className="k-title" fill="#22c55e">{t('keys.payout_title', undefined, 'Payout')}</text>
          <text x="812" y="102" className="k-sub">{t('keys.payout_released', undefined, 'bounty released')}</text>
        </g>

        {/* the separation firewall */}
        <line x1="540" y1="20" x2="540" y2="230" stroke="var(--sev-critical)" strokeWidth="1" strokeDasharray="4 6" opacity="0.5" />
        <text x="540" y="214" className="k-fire" fill="var(--sev-critical)">{t('keys.key_boundary', undefined, 'key boundary')}</text>
        <text x="270" y="214" className="k-fire2">{t('keys.momus_side_note', undefined, 'MOMUS side — finds & signs, cannot pay')}</text>
        <text x="740" y="214" className="k-fire2">{t('keys.treasury_side_note', undefined, 'Treasury side — pays, cannot find')}</text>
      </svg>
    </div>
  );
}
