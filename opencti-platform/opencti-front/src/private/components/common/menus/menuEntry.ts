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
  /** Entity type the page lists: the entry is hidden when the platform settings hide this exact type. */
  entityType?: string;
  /** Extra words matching this entry in the main search (aliases, CTI jargon...). */
  keywords?: string[];
  /** Page reached outside the left bar (top bar icons...): indexed in the main search without a left bar subsection, with this breadcrumb. */
  standaloneParents?: string[];
  /** Left bar entry active only on this exact path (not on its sub-routes). */
  exact?: boolean;
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

/** Pages grouped under one left bar row (Import, Security...), leading to the first visible one. Visible if one is. */
export interface NavSubSection {
  label: string;
  entries: MenuEntry[];
}

/**
 * Sub-item of a left bar section: a page (its `MenuEntry` owns the label, icon and access rules), or a sub-section.
 * Sections reference the entries themselves, not their paths.
 */
export type NavSectionItem = MenuEntry | NavSubSection;

interface NavSectionBase {
  id: string;
  /** Left bar block it belongs to. Blocks and sections keep the order of `navSections`. */
  group: string;
}

/** Top-level item without sub-items: a single page, its `MenuEntry` gives the label, icon and access rules. */
export interface NavPageSection extends NavSectionBase {
  page: MenuEntry;
}

/**
 * Top-level item opening sub-items. Visible if at least one of them is, and leads to the first visible one: it has no
 * access rule nor path of its own.
 */
export interface NavContainerSection extends NavSectionBase {
  label: string;
  icon: ReactElement;
  items: NavSectionItem[];
}

export type NavSection = NavPageSection | NavContainerSection;
