// The markings of the fixtures: plain data, without any import, so that a mock factory can load them
export const tlpAmber = {
  id: 'tlp-amber-id',
  internal_id: 'tlp-amber-id',
  standard_id: 'marking-definition--f88d31f6-486f-44da-b317-01333bde0b82',
  entity_type: 'Marking-Definition',
  definition_type: 'TLP',
  definition: 'TLP:AMBER',
};

export const papRed = {
  id: 'pap-red-id',
  internal_id: 'pap-red-id',
  standard_id: 'marking-definition--b2b9ab02-6b8f-4c8e-a5e5-0a8f3d4b5c6d',
  entity_type: 'Marking-Definition',
  definition_type: 'PAP',
  definition: 'PAP:RED',
};

export const customMarking = {
  id: 'custom-marking-id',
  internal_id: 'custom-marking-id',
  standard_id: 'marking-definition--8c4a2b0e-4b8e-5d3c-9b2a-1f6e7d8c9a0b',
  entity_type: 'Marking-Definition',
  definition_type: 'INTERNAL',
  definition: 'INTERNAL:SOC',
  x_opencti_color: '#123456',
  x_opencti_order: 7,
  creator_id: ['creator-secret-id'],
  created_at: '2026-01-01T00:00:00.000Z',
};

export const ALL_MARKINGS = [tlpAmber, papRed, customMarking];
