import {
    ENTITY_TYPE_IDENTITY_SECTOR,
    ENTITY_TYPE_INCIDENT,
    ENTITY_TYPE_LOCATION_COUNTRY,
    ENTITY_TYPE_THREAT_ACTOR_GROUP
} from '../../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../../../src/modules/organization/organization-types';
import { ENTITY_TYPE_EXTERNAL_REFERENCE } from '../../../../src/schema/stixMetaObject';
import { RELATION_LOCATED_AT, RELATION_PART_OF, RELATION_TARGETS } from '../../../../src/schema/stixCoreRelationship';
import type { BasicStoreEntityCsvMapper } from '../../../../src/modules/internal/csvMapper/csvMapper-types';
import { CsvMapperRepresentationType } from '../../../../src/modules/internal/csvMapper/csvMapper-types';

export const csvMapperMockRealUseCase: Partial<BasicStoreEntityCsvMapper> = {
    id: 'mapper-mock-simple-entity',
    has_header: true,
    separator: ',',
    representations: [
        // ENTITIES
        {
            id: 'representationIncident01',
            type: CsvMapperRepresentationType.entity,
            target: {
                entity_type: ENTITY_TYPE_INCIDENT,
            },
            attributes: [
                {
                    key: 'first_seen',
                    column: {
                        column_name: 'B',
                        configuration: {
                            pattern_date: 'DD-MM-YYYY',
                            timezone: 'Europe/Paris',
                        }
                    },
                },
                {
                    key: 'name',
                    column: {
                        column_name: 'F',
                    },
                },
                {
                    key: 'incident_type',
                    column: {
                        column_name: 'G',
                    },
                },
                {
                    key: 'severity',
                    column: {
                        column_name: 'K',
                    },
                },
                {
                    key: 'description',
                    column: {
                        column_name: 'O',
                    },
                },
                {
                    key: 'externalReferences',
                    based_on: {
                        representations: ['representationExternalRef01', 'representationExternalRef02'],
                    }
                },
            ]
        },
        {
            id: 'representationCountry01',
            type: CsvMapperRepresentationType.entity,
            target: {
                entity_type: ENTITY_TYPE_LOCATION_COUNTRY,
            },
            attributes: [
                {
                    key: 'name',
                    column: {
                        column_name: 'D',
                    },
                },
            ]
        },
        {
            id: 'representationCountry02',
            type: CsvMapperRepresentationType.entity,
            target: {
                entity_type: ENTITY_TYPE_LOCATION_COUNTRY,
            },
            attributes: [
                {
                    key: 'name',
                    column: {
                        column_name: 'E',
                    },
                },
            ]
        },
        {
            id: 'representationSector01',
            type: CsvMapperRepresentationType.entity,
            target: {
                entity_type: ENTITY_TYPE_IDENTITY_SECTOR,
            },
            attributes: [
                {
                    key: 'name',
                    column: {
                        column_name: 'H',
                    },
                },
            ]
        },
        {
            id: 'representationSector02',
            type: CsvMapperRepresentationType.entity,
            target: {
                entity_type: ENTITY_TYPE_IDENTITY_SECTOR,
            },
            attributes: [
                {
                    key: 'name',
                    column: {
                        column_name: 'I',
                    },
                },
            ]
        },
        {
            id: 'representationThreat01',
            type: CsvMapperRepresentationType.entity,
            target: {
                entity_type: ENTITY_TYPE_THREAT_ACTOR_GROUP,
            },
            attributes: [
                {
                    key: 'name',
                    column: {
                        column_name: 'L',
                    },
                },
                {
                    key: 'threat_actor_types',
                    column: {
                        column_name: 'N',
                    },
                },
                {
                    key: 'primary_motivation',
                    column: {
                        column_name: 'S',
                    },
                },
            ]
        },
        {
            id: 'representationOrganization01',
            type: CsvMapperRepresentationType.entity,
            target: {
                entity_type: ENTITY_TYPE_IDENTITY_ORGANIZATION,
            },
            attributes: [
                {
                    key: 'name',
                    column: {
                        column_name: 'M',
                    },
                },
            ]
        },
        // META
        {
            id: 'representationExternalRef01',
            type: CsvMapperRepresentationType.entity,
            target: {
                entity_type: ENTITY_TYPE_EXTERNAL_REFERENCE,
            },
            attributes: [
                {
                    key: 'source_name',
                    column: {
                        column_name: 'Q',
                    },
                },
                {
                    key: 'url',
                    column: {
                        column_name: 'Q',
                    },
                },
            ]
        },
        {
            id: 'representationExternalRef02',
            type: CsvMapperRepresentationType.entity,
            target: {
                entity_type: ENTITY_TYPE_EXTERNAL_REFERENCE,
            },
            attributes: [
                {
                    key: 'source_name',
                    column: {
                        column_name: 'R',
                    },
                },
                {
                    key: 'url',
                    column: {
                        column_name: 'R',
                    },
                },
            ]
        },
        // RELATIONSHIPS
        {
            id: 'representationOrganization01-LOCATED_AT-representationCountry01',
            type: CsvMapperRepresentationType.relationship,
            target: {
                entity_type: RELATION_LOCATED_AT,
            },
            attributes: [
                {
                    key: 'from',
                    based_on: {
                        representations: ['representationOrganization01'],
                    }
                },
                {
                    key: 'to',
                    based_on: {
                        representations: ['representationCountry01'],
                    }
                }
            ]
        },
        {
            id: 'representationOrganization01-LOCATED_AT-representationCountry02',
            type: CsvMapperRepresentationType.relationship,
            target: {
                entity_type: RELATION_LOCATED_AT,
            },
            attributes: [
                {
                    key: 'from',
                    based_on: {
                        representations: ['representationOrganization01'],
                    }
                },
                {
                    key: 'to',
                    based_on: {
                        representations: ['representationCountry02'],
                    }
                }
            ]
        },
        {
            id: 'representationOrganization01-PART_OF-representationSector01',
            type: CsvMapperRepresentationType.relationship,
            target: {
                entity_type: RELATION_PART_OF,
            },
            attributes: [
                {
                    key: 'from',
                    based_on: {
                        representations: ['representationOrganization01'],
                    }
                },
                {
                    key: 'to',
                    based_on: {
                        representations: ['representationSector01'],
                    }
                }
            ]
        },
        {
            id: 'representationOrganization01-PART_OF-representationSector02',
            type: CsvMapperRepresentationType.relationship,
            target: {
                entity_type: RELATION_PART_OF,
            },
            attributes: [
                {
                    key: 'from',
                    based_on: {
                        representations: ['representationOrganization01'],
                    }
                },
                {
                    key: 'to',
                    based_on: {
                        representations: ['representationSector02'],
                    }
                }
            ]
        },
        {
            id: 'representationThreat01-TARGET-representationOrganization01',
            type: CsvMapperRepresentationType.relationship,
            target: {
                entity_type: RELATION_TARGETS,
            },
            attributes: [
                {
                    key: 'from',
                    based_on: {
                        representations: ['representationThreat01'],
                    }
                },
                {
                    key: 'to',
                    based_on: {
                        representations: ['representationOrganization01'],
                    }
                }
            ]
        }
    ]
}
