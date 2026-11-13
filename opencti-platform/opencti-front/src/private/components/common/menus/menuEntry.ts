import type { ReactElement } from 'react';

// Pure type, no component import: the `*.entries.ts(x)` files import it (see their ESLint rule).
export interface MenuEntry {
  path: string;
  label: string;
  icon?: ReactElement;
  /** Visible for everyone, with an EE chip (the page itself shows the EE lock). */
  isEE?: boolean;
  /** Entry hidden unless the platform has a valid Enterprise Edition licence. */
  requiresEE?: boolean;
  /** Extra words matching this entry in the main search (aliases, CTI jargon...). */
  keywords?: string[];
  /** Page reached outside the left bar (top bar icons...): indexed in the main search without a left bar subsection, with this breadcrumb. */
  standaloneParents?: string[];
  /** Entry hidden if the user has none of these capabilities: ANY one is enough (never "all of"). */
  requiredCapabilities?: string[];
  /** Also granted if the user has one of these capabilities in a draft (see `useGranted` options). */
  capabilitiesInDraft?: string[];
  /** Entry hidden if this feature flag is off. */
  featureFlag?: string;
  /**
   * Entry kept when the user is in a draft context. Off by default: a page is not available in draft unless it says so.
   * Only effective if the page's left bar section is also shown in draft (see `useNavMenu`).
   */
  availableInDraft?: boolean;
}
