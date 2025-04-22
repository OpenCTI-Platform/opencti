interface PIRCriterion {
  standard_id: string
  // weight: number
}

interface PIR {
  id: string
  name: string
  criteria: PIRCriterion[]
}

export const FAKE_PIR: PIR = {
  id: '2b271fe3-8fdb-4df4-9b1f-bc55202dfa23',
  name: 'PIR about Energy sector in France',
  criteria: [
    { standard_id: 'location--b8d0549f-de06-5ebd-a6e9-d31a581dba5d' },
    { standard_id: 'identity--166544e2-ba1f-5a6c-89cf-a63d0c01e91c' },
  ]
};
