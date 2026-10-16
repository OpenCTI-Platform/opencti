import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { ENTITY_TYPE_IDENTITY } from '../../schema/general';
import { NAME_FIELD, normalizeName } from '../../schema/identifier';
import {
  ENTITY_TYPE_IDENTITY_CITIZENSHIP_DOCUMENT,
  type Stix2CitizenshipDocument,
  type StixCitizenshipDocument,
  type StoreEntityCitizenshipDocument,
} from './citizenshipDocument-types';
import convertCitizenshipDocumentToStix, { convertCitizenshipDocumentToStix_2_0 } from './citizenshipDocument-converter';
import { RELATION_SHOULD_COVER } from '../../schema/stixCoreRelationship';
import { REL_NEW } from '../../database/stix';
import { ENTITY_TYPE_ATTACK_PATTERN } from '../../schema/stixDomainObject';
import { objectOrganization } from '../../schema/stixRefRelationship';

const CITIZENSHIP_DOCUMENT_DEFINITION: ModuleDefinition<StoreEntityCitizenshipDocument, StixCitizenshipDocument, Stix2CitizenshipDocument> = {
  type: {
    id: 'citizenship-document',
    name: ENTITY_TYPE_IDENTITY_CITIZENSHIP_DOCUMENT,
    category: ENTITY_TYPE_IDENTITY,
    aliased: false,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_IDENTITY_CITIZENSHIP_DOCUMENT]: [{ src: NAME_FIELD }, { src: 'identity_class', dependencies: [NAME_FIELD] }],
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
    { name: 'x_opencti_citizenship_document_type', label: 'Citizenship document type', type: 'string', format: 'vocabulary', vocabularyCategory: 'citizenship_document_type_ov', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
  ],
  relations: [
    {
      name: RELATION_SHOULD_COVER,
      targets: [
        { name: ENTITY_TYPE_ATTACK_PATTERN, type: REL_NEW },
      ],
    },
  ],
  relationsRefs: [
    { ...objectOrganization, isFilterable: false },
  ],
  representative: (stix: StixCitizenshipDocument) => {
    return stix.name;
  },
  converter_2_1: convertCitizenshipDocumentToStix,
  converter_2_0: convertCitizenshipDocumentToStix_2_0,
};

registerDefinition(CITIZENSHIP_DOCUMENT_DEFINITION);
