import type { BasicStoreEntityExclusionList } from '../../../../src/modules/exclusionList/exclusionList-types';

// An exclusion list of IP addresses, and a disabled one without description. The id of an exclusion list is random on every platform;
// its values are a file of the storage, whose name is `<internal id>.txt`.
export const dnsExclusionList = {
  id: 'dns-exclusion-list-id',
  internal_id: 'dns-exclusion-list-id',
  standard_id: '3f1d0c4e-7a52-4b8e-9f3a-1c2d3e4f5a6b',
  entity_type: 'ExclusionList',
  creator_id: ['creator-secret-id'],
  created_at: '2026-01-01T00:00:00.000Z',
  name: 'Public DNS resolvers',
  description: 'Well-known resolvers',
  enabled: true,
  exclusion_list_entity_types: ['IPv4-Addr'],
  file_id: 'exclusionLists/dns-exclusion-list-id.txt',
  exclusion_list_values_count: 3,
  exclusion_list_file_size: 22,
} as unknown as BasicStoreEntityExclusionList;

export const retiredExclusionList = {
  ...dnsExclusionList,
  id: 'retired-exclusion-list-id',
  internal_id: 'retired-exclusion-list-id',
  standard_id: '9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d',
  name: 'Retired partners',
  description: undefined,
  enabled: false,
  exclusion_list_entity_types: ['Domain-Name', 'Hostname'],
  file_id: 'exclusionLists/retired-exclusion-list-id.txt',
} as unknown as BasicStoreEntityExclusionList;

export const ALL_EXCLUSION_LISTS = [dnsExclusionList, retiredExclusionList];
