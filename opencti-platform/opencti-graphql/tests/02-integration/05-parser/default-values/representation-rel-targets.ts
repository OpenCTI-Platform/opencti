import { type CsvMapperRepresentation, CsvMapperRepresentationType } from '../../../../src/modules/internal/csvMapper/csvMapper-types';
import { RELATION_TARGETS } from '../../../../src/schema/stixCoreRelationship';

export const repRelTargets: CsvMapperRepresentation = {
  id: 'representation-targets',
  type: CsvMapperRepresentationType.Relationship,
  target: {
    entity_type: RELATION_TARGETS,
  },
  attributes: [
    {
      key: 'from',
      based_on: {
        representations: ['representation-malware-default']
      }
    },
    {
      key: 'to',
      based_on: {
        representations: ['representation-area-default']
      }
    },
    {
      key: 'confidence',
      default_values: ['77'],
    }
  ]
};
