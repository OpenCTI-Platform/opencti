import openAevMark from '../../../../../../static/images/logo_oaev.svg';
import openCrqMark from '../../../../../../static/images/logo_ocrq.svg';
import { OPENAEV_FACTS, OPENCRQ_FACTS, type FactDefinition } from './counterpartFacts';

// The XTM products an OpenCTI object can have a counterpart in, in the order the emblems are drawn
// (Contract v3: OpenCTI, OpenAEV, OpenCRQ, skipping self). Every string a product needs lives here,
// so the header, the list rows and the alert card never name a product themselves.

export interface XtmProduct {
  product: string;
  name: string;
  mark: string;
  facts: ReadonlyArray<FactDefinition>;
  // The accessible name and tooltip title of each state, i18n keys written out so the checker sees them.
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
}

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

export const XTM_PRODUCTS: ReadonlyArray<XtmProduct> = [OPENAEV_PRODUCT, OPENCRQ_PRODUCT];

/** The products that can hold a counterpart of this OpenCTI entity type, in emblem order. */
export const xtmProductsFor = (entityType: string | null | undefined): XtmProduct[] => (
  entityType ? XTM_PRODUCTS.filter((p) => p.entityTypes.includes(entityType)) : []
);
