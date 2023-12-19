import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import type { StixOrganization, StoreEntityOrganization } from './organization-types';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from './organization-types';
import { ENTITY_TYPE_IDENTITY } from '../../schema/general';
import organizationTypeDefs from './organization.graphql';
import organizationResolvers from './organization-resolver';
import { NAME_FIELD, normalizeName } from '../../schema/identifier';
import { iAliasedIds, xOpenctiAliases, xOpenctiReliability } from '../../schema/attribute-definition';
import { RELATION_LOCATED_AT, RELATION_PART_OF, RELATION_PUBLISHES, RELATION_USES } from '../../schema/stixCoreRelationship';
import {
  ENTITY_TYPE_IDENTITY_SECTOR,
  ENTITY_TYPE_LOCATION_CITY,
  ENTITY_TYPE_LOCATION_COUNTRY,
  ENTITY_TYPE_LOCATION_POSITION,
  ENTITY_TYPE_LOCATION_REGION,
  ENTITY_TYPE_TOOL
} from '../../schema/stixDomainObject';
import { REL_BUILT_IN, REL_EXTENDED, REL_NEW } from '../../database/stix';
import { ENTITY_MEDIA_CONTENT } from '../../schema/stixCyberObservable';
import { ENTITY_TYPE_LOCATION_ADMINISTRATIVE_AREA } from '../administrativeArea/administrativeArea-types';
import convertOrganizationToStix from './organization-converter';

const ORGANIZATION_DEFINITION: ModuleDefinition<StoreEntityOrganization, StixOrganization> = {
  type: {
    id: 'organization',
    name: ENTITY_TYPE_IDENTITY_ORGANIZATION,
    category: ENTITY_TYPE_IDENTITY
  },
  graphql: {
    schema: organizationTypeDefs,
    resolver: organizationResolvers,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_IDENTITY_ORGANIZATION]: [{ src: NAME_FIELD }, { src: 'identity_class' }]
    },
    resolvers: {
      name(data: object) {
        return normalizeName(data);
      },
    },
  },
  attributes: [
    xOpenctiAliases,
    iAliasedIds,
    xOpenctiReliability,
    { name: 'default_dashboard', label: 'Default dashboard', type: 'string', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'x_opencti_organization_type', label: 'Organization type', type: 'string', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'default_hidden_types', label: 'Default hidden types', type: 'string', mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, isFilterable: true },
    { name: 'authorized_authorities', label: 'Authorized authorities', type: 'string', mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, isFilterable: false },
    { name: 'grantable_groups', label: 'Grantable groups', type: 'string', mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, isFilterable: true },
  ],
  relations: [
    {
      name: RELATION_PART_OF,
      targets: [
        { name: ENTITY_TYPE_IDENTITY_ORGANIZATION, type: REL_NEW },
        { name: ENTITY_TYPE_IDENTITY_SECTOR, type: REL_NEW },
      ]
    },
    {
      name: RELATION_LOCATED_AT,
      targets: [
        { name: ENTITY_TYPE_LOCATION_POSITION, type: REL_BUILT_IN },
        { name: ENTITY_TYPE_LOCATION_CITY, type: REL_BUILT_IN },
        { name: ENTITY_TYPE_LOCATION_ADMINISTRATIVE_AREA, type: REL_BUILT_IN },
        { name: ENTITY_TYPE_LOCATION_COUNTRY, type: REL_BUILT_IN },
        { name: ENTITY_TYPE_LOCATION_REGION, type: REL_BUILT_IN },
      ]
    },
    {
      name: RELATION_USES,
      targets: [
        { name: ENTITY_TYPE_TOOL, type: REL_EXTENDED },
      ]
    },
    {
      name: RELATION_PUBLISHES,
      targets: [
        { name: ENTITY_MEDIA_CONTENT, type: REL_NEW },
      ]
    },
  ],
  representative: (stix: StixOrganization) => {
    return stix.name;
  },
  converter: convertOrganizationToStix
};
registerDefinition(ORGANIZATION_DEFINITION);
