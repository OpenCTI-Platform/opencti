// The product glyphs of the design system's product switcher, the same files in the three products.
import openAevMark from '../../../../../../static/images/xtm/xtm-mark-openaev.svg';
import openCrqMark from '../../../../../../static/images/xtm/xtm-mark-opencrq.svg';
import xtmOneMark from '../../../../../../static/images/xtm/xtm-mark-xtmone.svg';
import { OPENAEV_FACTS, OPENCRQ_FACTS, XTMONE_FACTS, type FactDefinition } from './counterpartFacts';

// The XTM products an OpenCTI object can have a counterpart in, in the order their sections are
// drawn in the XTM surface (XTM One first, then OpenAEV, OpenCRQ). Every string a product needs
// lives here, so the header, the list rows and the alert card never name a product themselves.

export interface XtmProduct {
  product: string;
  name: string;
  mark: string;
  facts: ReadonlyArray<FactDefinition>;
  // The accessible name and tooltip title of each state, as i18n keys. The i18n scanners read only
  // .jsx/.tsx files, so they do not see this file: these keys are kept in the catalogs by hand.
  open: string;
  notFound: string;
  unavailable: string;
  connect: string;
  notConnected: string;
  // One line under the preview of a match: what the click opens.
  action: string;
  // One line under "Not found in X": how an object gets there.
  howItGetsThere: string;
  // The teaser of a product that is not connected: why connecting is worth it.
  pitch: string;
  // OpenCTI entity types the product holds a counterpart for (no emblem on the other types).
  entityTypes: ReadonlyArray<string>;
  // The ink of the found emblem: the theme highlight, or the product's own brand ink (XTM One purple).
  foundColor?: string;
}

// XTM One's inventory holds assets only: its emblem is drawn on systems, as OpenAEV's asset emblem.
export const XTMONE_PRODUCT: XtmProduct = {
  product: 'xtmone',
  name: 'XTM One',
  mark: xtmOneMark,
  facts: XTMONE_FACTS,
  open: 'Open in XTM One',
  notFound: 'Not found in XTM One',
  unavailable: 'XTM One is unavailable',
  connect: 'Connect XTM One',
  notConnected: 'XTM One is not connected',
  action: 'See this asset in the XTM One inventory: its criticality, owner and exposure.',
  howItGetsThere: 'It appears once the XTM One inventory holds an asset with this hostname or address.',
  pitch: 'Connect XTM One to see this asset in your inventory.',
  entityTypes: ['System'],
  // The canonical XTM One purple of the design system (--color-filigran-ia-primary: dark #a47af0,
  // light #651fe5), the colour of the XTM One mark in the product switcher.
  foundColor: 'var(--color-filigran-ia-primary)',
};

export const OPENAEV_PRODUCT: XtmProduct = {
  product: 'openaev',
  name: 'OpenAEV',
  mark: openAevMark,
  facts: OPENAEV_FACTS,
  open: 'Open in OpenAEV',
  notFound: 'Not found in OpenAEV',
  unavailable: 'OpenAEV is unavailable',
  connect: 'Connect OpenAEV',
  notConnected: 'OpenAEV is not connected',
  action: 'See the simulations, findings and exposed assets of this object in OpenAEV.',
  howItGetsThere: 'It appears once a simulation or a collector in OpenAEV uses it.',
  pitch: 'Connect OpenAEV to see how this object is simulated and what it exposes.',
  entityTypes: ['System', 'Attack-Pattern', 'Vulnerability', 'Malware', 'Intrusion-Set', 'Campaign', 'Threat-Actor-Group', 'Threat-Actor-Individual', 'Incident', 'stix-sighting-relationship'],
};

export const OPENCRQ_PRODUCT: XtmProduct = {
  product: 'opencrq',
  name: 'OpenCRQ',
  mark: openCrqMark,
  facts: OPENCRQ_FACTS,
  open: 'Open in OpenCRQ',
  notFound: 'Not found in OpenCRQ',
  unavailable: 'OpenCRQ is unavailable',
  connect: 'Connect OpenCRQ',
  notConnected: 'OpenCRQ is not connected',
  action: 'See the financial impact of this object and the risk scenarios it drives in OpenCRQ.',
  howItGetsThere: 'It appears once a risk scenario in OpenCRQ uses it.',
  pitch: 'Connect OpenCRQ to see the annual loss this object drives.',
  entityTypes: ['System', 'Vulnerability', 'Malware', 'Intrusion-Set', 'Campaign', 'Threat-Actor-Group', 'Threat-Actor-Individual'],
};

export const XTM_PRODUCTS: ReadonlyArray<XtmProduct> = [XTMONE_PRODUCT, OPENAEV_PRODUCT, OPENCRQ_PRODUCT];

/** The products that can hold a counterpart of this OpenCTI entity type, in emblem order. */
export const xtmProductsFor = (entityType: string | null | undefined): XtmProduct[] => (
  entityType ? XTM_PRODUCTS.filter((p) => p.entityTypes.includes(entityType)) : []
);
