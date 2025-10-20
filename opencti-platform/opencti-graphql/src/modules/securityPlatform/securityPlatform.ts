import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { ENTITY_TYPE_IDENTITY } from '../../schema/general';
import { NAME_FIELD, normalizeName } from '../../schema/identifier';
import { ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM, type StixSecurityPlatform, type StoreEntitySecurityPlatform } from './securityPlatform-types';
import convertSecurityPlatformToStix from './securityPlatform-converter';
import { RELATION_SHOULD_COVER } from '../../schema/stixCoreRelationship';
import { REL_NEW } from '../../database/stix';
import { ENTITY_TYPE_ATTACK_PATTERN } from '../../schema/stixDomainObject';
import { objectOrganization } from '../../schema/stixRefRelationship';

const SECURITY_PLATFORM_DEFINITION: ModuleDefinition<StoreEntitySecurityPlatform, StixSecurityPlatform> = {
  type: {
    id: 'security-platform',
    name: ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM,
    category: ENTITY_TYPE_IDENTITY,
    aliased: false,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM]: [{ src: NAME_FIELD }, { src: 'identity_class', dependencies: [NAME_FIELD] }]
    },
    resolvers: {
      name(data: object) {
        return normalizeName(data);
      },
      identity_class(data: object) {
        return normalizeName(data);
      },
    },
  },
  attributes: [
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'security_platform_type', label: 'Security platform type', type: 'string', format: 'vocabulary', vocabularyCategory: 'security_platform_type_ov', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
  ],
  relations: [
    {
      name: RELATION_SHOULD_COVER,
      targets: [
        { name: ENTITY_TYPE_ATTACK_PATTERN, type: REL_NEW },
      ]
    },
  ],
  relationsRefs: [
    { ...objectOrganization, isFilterable: false }
  ],
  representative: (stix: StixSecurityPlatform) => {
    return stix.name;
  },
  converter_2_1: convertSecurityPlatformToStix
};

registerDefinition(SECURITY_PLATFORM_DEFINITION);
