import { CsvMapperRepresentationType } from '../../../../src/modules/internal/csvMapper/csvMapper-types';
import { RELATION_TARGETS } from '../../../../src/schema/stixCoreRelationship';
export const repRelTargets = {
    id: 'representation-targets',
    type: CsvMapperRepresentationType.relationship,
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
