import { type CsvMapperRepresentation, CsvMapperRepresentationType } from '../../../../src/modules/internal/csvMapper/csvMapper-types';
import { ENTITY_TYPE_KILL_CHAIN_PHASE } from '../../../../src/schema/stixMetaObject';

export const repKillChainPhase: CsvMapperRepresentation = {
  id: 'representation-killchainphase',
  type: CsvMapperRepresentationType.entity,
  target: {
    entity_type: ENTITY_TYPE_KILL_CHAIN_PHASE,
  },
  attributes: [
    {
      key: 'kill_chain_name',
      column: {
        column_name: 'K',
      },
    },
    {
      key: 'phase_name',
      column: {
        column_name: 'L',
      },
    },
    {
      key: 'x_opencti_order',
      column: {
        column_name: 'M',
      },
    },
  ]
};
