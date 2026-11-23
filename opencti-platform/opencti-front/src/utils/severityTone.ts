import type { ChipSeverity } from '@filigran/design-system';

/**
 * The predefined levels of OpenCTI mapped to the design-system chip tones, so a
 * severity, a priority, a score or a TLP/PAP marking draws the same standard colour
 * as in XTM One, OpenAEV and OpenCRQ when the user turns "Pastel colours" off, and
 * the pastel fill otherwise (the `pastel` class on the document root; on by default
 * in OpenCTI so existing users see no change).
 *
 * | tone     | token family     | used for                                   |
 * |----------|------------------|--------------------------------------------|
 * | critical | feedback-error   | critical, P1, score > 75, TLP:RED, PAP:RED |
 * | high     | feedback-warning | high, P2, score 51-75, TLP:AMBER, PAP:AMBER|
 * | medium   | feedback-alert   | medium, P3                                 |
 * | low      | feedback-success | low, P4, score <= 20, TLP:GREEN, PAP:GREEN |
 * | info     | feedback-info    | score 21-50, TLP:CLEAR, SF                 |
 * | neutral  | feedback-neutral | anything else                              |
 */
export const severityTone = (severity?: string | null): ChipSeverity => {
  switch (severity?.toLowerCase()) {
    case 'critical':
      return 'critical';
    case 'high':
      return 'high';
    case 'medium':
      return 'medium';
    case 'low':
      return 'low';
    case 'info':
      return 'info';
    default:
      return 'neutral';
  }
};

export const priorityTone = (priority?: string | null): ChipSeverity => {
  switch (priority) {
    case 'P1':
      return 'critical';
    case 'P2':
      return 'high';
    case 'P3':
      return 'medium';
    case 'P4':
      return 'low';
    default:
      return 'neutral';
  }
};

/** Score out of 100 (indicators, observables): the bands ItemScore always drew. */
export const scoreTone = (score: number): ChipSeverity => {
  if (score <= 20) return 'low';
  if (score <= 50) return 'info';
  if (score <= 75) return 'high';
  if (score <= 100) return 'critical';
  return 'neutral';
};

/**
 * CVSS base score (0-10): the bands ItemCvssScore always drew. Every score above 7
 * up to 10 takes the critical tone, so the most severe band follows the shared tones
 * like every other XTM module.
 */
export const cvssTone = (cvssScore: number): ChipSeverity => {
  if (cvssScore === 0) return 'neutral';
  if (cvssScore <= 3) return 'low';
  if (cvssScore <= 5) return 'info';
  if (cvssScore <= 7) return 'high';
  if (cvssScore <= 10) return 'critical';
  return 'neutral';
};

/**
 * Predefined marking definitions (TLP, PAP, the French DR/NP/SF/CD levels): the same
 * tones in OpenCTI, OpenAEV and OpenCRQ, whatever colour the built-in marking stores.
 * `null` for NONE (a plain chip), `undefined` for a custom marking, which keeps the
 * colour its administrator stored (ItemMarkings).
 */
export const markingTone = (definition?: string | null): ChipSeverity | null | undefined => {
  switch (definition) {
    case 'CD':
    case 'CD-SF':
    case 'DR':
    case 'DR-SF':
    case 'TLP:RED':
    case 'PAP:RED':
      return 'critical';
    case 'TLP:AMBER':
    case 'TLP:AMBER+STRICT':
    case 'PAP:AMBER':
      return 'high';
    case 'NP':
    case 'TLP:GREEN':
    case 'PAP:GREEN':
      return 'low';
    case 'SF':
      return 'info';
    case 'TLP:CLEAR':
    case 'PAP:CLEAR':
      return 'neutral';
    case 'NONE':
      return null;
    default:
      return undefined;
  }
};
