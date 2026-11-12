import type { BasicStoreEntityFintelDesign } from '../../../../src/modules/fintelDesign/fintelDesign-types';

// The default fintel design of the platform, with a logo, next to the import format fields, attributes that must never be exported.
// The logo of a design is a file of the storage, stored under its internal id without extension.
export const defaultFintelDesign = {
  id: 'default-fintel-design-id',
  internal_id: 'default-fintel-design-id',
  standard_id: 'finteldesign--2c5e8f1a-4b3d-5e6f-8a9b-0c1d2e3f4a5b',
  entity_type: 'FintelDesign',
  creator_id: ['creator-secret-id'],
  created_at: '2026-01-01T00:00:00.000Z',
  name: 'Filigran report',
  description: 'The design of the reports',
  gradiantFromColor: '#00020c',
  gradiantToColor: '#001bda',
  textColor: '#ffffff',
  default: true,
  file_id: 'fintelDesigns/default-fintel-design-id',
} as unknown as BasicStoreEntityFintelDesign;

// A design that is not the default, without logo nor description
export const nightFintelDesign = {
  ...defaultFintelDesign,
  id: 'night-fintel-design-id',
  internal_id: 'night-fintel-design-id',
  standard_id: 'finteldesign--7a8b9c0d-1e2f-5a3b-9c4d-5e6f7a8b9c0d',
  name: 'Night briefing',
  description: undefined,
  textColor: null,
  default: false,
  file_id: undefined,
} as unknown as BasicStoreEntityFintelDesign;

export const ALL_FINTEL_DESIGNS = [defaultFintelDesign, nightFintelDesign];

// A PNG signature followed by some bytes: what the format of a logo is recognized from
export const PNG_LOGO = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.from('png-logo-bytes')]);
