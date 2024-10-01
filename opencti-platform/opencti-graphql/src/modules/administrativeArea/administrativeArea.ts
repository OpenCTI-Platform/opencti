import convertAdministrativeAreaToStix from './administrativeArea-converter';
import { NAME_FIELD, normalizeName } from '../../schema/identifier';
import { ENTITY_TYPE_LOCATION_ADMINISTRATIVE_AREA, type StoreEntityAdministrativeArea } from './administrativeArea-types';
import { REL_BUILT_IN } from '../../database/stix';
import { RELATION_DERIVED_FROM, RELATION_LOCATED_AT } from '../../schema/stixCoreRelationship';
import { ENTITY_TYPE_LOCATION_COUNTRY, ENTITY_TYPE_LOCATION_REGION } from '../../schema/stixDomainObject';
import { ENTITY_TYPE_LOCATION } from '../../schema/general';
import type { StixLocation } from '../../types/stix-sdo';
import type { ModuleDefinition } from '../../schema/module';
import { registerDefinition } from '../../schema/module';
import { entityLocationType } from '../../schema/attribute-definition';

const ADMINISTRATIVE_AREA_DEFINITION: ModuleDefinition<StoreEntityAdministrativeArea, StixLocation> = {
  type: {
    id: 'administrativeAreas',
    name: ENTITY_TYPE_LOCATION_ADMINISTRATIVE_AREA,
    category: ENTITY_TYPE_LOCATION,
    aliased: true
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_LOCATION_ADMINISTRATIVE_AREA]: [{ src: NAME_FIELD }]
    },
    resolvers: {
      name(data: object) {
        return normalizeName(data);
      },
    },
  },
  attributes: [
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'latitude', label: 'Latitude', type: 'numeric', precision: 'float', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: false },
    { name: 'longitude', label: 'Longitude', type: 'numeric', precision: 'float', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: false },
    entityLocationType,
  ],
  relations: [
    {
      name: RELATION_LOCATED_AT,
      targets: [
        { name: ENTITY_TYPE_LOCATION_COUNTRY, type: REL_BUILT_IN },
        { name: ENTITY_TYPE_LOCATION_REGION, type: REL_BUILT_IN },
      ]
    },
    {
      name: RELATION_DERIVED_FROM,
      targets: [
        { name: ENTITY_TYPE_LOCATION_ADMINISTRATIVE_AREA, type: REL_BUILT_IN }
      ]
    }
  ],
  representative(instance: StixLocation): string {
    return instance.name;
  },
  converter: convertAdministrativeAreaToStix
};

registerDefinition(ADMINISTRATIVE_AREA_DEFINITION);
