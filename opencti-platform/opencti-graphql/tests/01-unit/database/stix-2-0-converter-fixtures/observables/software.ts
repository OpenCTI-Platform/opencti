import type { StoreCyberObservable } from '../../../../../src/types/store';

export const SOFTWARE_INSTANCE = {
  id: '10000000-0000-4000-8000-000000000034',
  standard_id: 'software--20000000-0000-4000-8000-000000000034',
  entity_type: 'Software',
  defanged: false,
  name: 'Cobalt Strike',
  cpe: 'cpe:2.3:a:cobaltstrike:beacon:4.0:*:*:*:*:*:*:*',
  vendor: 'HelpSystems',
  version: '4.0',
  languages: ['en'],
  x_opencti_product: 'Cobalt Strike Beacon',
  objectMarking: [],
} as unknown as StoreCyberObservable;

export const EXPECTED_SOFTWARE = {
  id: 'software--20000000-0000-4000-8000-000000000034',
  type: 'software',
  spec_version: '2.0',
  x_opencti_id: '10000000-0000-4000-8000-000000000034',
  x_opencti_type: 'Software',
  x_opencti_granted_refs: [],
  x_opencti_files: [],
  defanged: false,
  object_marking_refs: [],
  x_opencti_labels: [],
  x_opencti_external_references: [],
  name: 'Cobalt Strike',
  cpe: 'cpe:2.3:a:cobaltstrike:beacon:4.0:*:*:*:*:*:*:*',
  vendor: 'HelpSystems',
  version: '4.0',
  languages: ['en'],
  x_opencti_product: 'Cobalt Strike Beacon',
};

