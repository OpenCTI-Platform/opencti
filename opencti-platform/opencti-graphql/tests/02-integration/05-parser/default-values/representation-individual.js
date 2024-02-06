import { CsvMapperRepresentationType } from '../../../../src/modules/internal/csvMapper/csvMapper-types';
import { ENTITY_TYPE_IDENTITY_INDIVIDUAL } from '../../../../src/schema/stixDomainObject';
export const repIndividual = {
    id: 'representation-individual',
    type: CsvMapperRepresentationType.entity,
    target: {
        entity_type: ENTITY_TYPE_IDENTITY_INDIVIDUAL,
    },
    attributes: [
        {
            key: 'name',
            column: {
                column_name: 'A',
            },
        },
    ]
};
