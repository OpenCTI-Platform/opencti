import { v4 as uuidv4 } from 'uuid';
import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { ABSTRACT_STIX_CYBER_OBSERVABLE, ABSTRACT_STIX_DOMAIN_OBJECT, ENTITY_TYPE_IDENTITY } from '../../schema/general';
import { createdAt, creators, updatedAt } from '../../schema/attribute-definition';
import { createdBy, killChainPhases, objectLabel, objectMarking, objectOrganization } from '../../schema/stixRefRelationship';
import { ENTITY_PROCESS } from '../../schema/stixCyberObservable';
import { ENTITY_TYPE_ATTACK_PATTERN, ENTITY_TYPE_MALWARE, ENTITY_TYPE_TOOL, isStixDomainObjectIdentity } from '../../schema/stixDomainObject';
import { RELATION_EXPLOITS, RELATION_HAS_OBSERVABLE, RELATION_IMPLEMENTS_TECHNIQUE, RELATION_USES } from '../../schema/stixCoreRelationship';
import { REL_EXTENDED, REL_NEW } from '../../database/stix';
import { ENTITY_TYPE_VULNERABILITY } from '../vulnerability/vulnerability-types';
import convertProcedureToStix from './procedure-converter';
import './procedure-components';
import {
  ATTRIBUTE_COMMAND_REF,
  ATTRIBUTE_SOURCE_REFS,
  ENTITY_TYPE_PROCEDURE,
  INPUT_PROCEDURE_COMMAND,
  INPUT_PROCEDURE_SOURCES,
  RELATION_PROCEDURE_COMMAND,
  RELATION_PROCEDURE_SOURCE,
  type StixProcedure,
  type StoreEntityProcedure,
} from './procedure-types';

const PROCEDURE_DEFINITION: ModuleDefinition<StoreEntityProcedure, StixProcedure> = {
  type: {
    id: 'procedures',
    name: ENTITY_TYPE_PROCEDURE,
    category: ABSTRACT_STIX_DOMAIN_OBJECT,
    aliased: false,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_PROCEDURE]: () => uuidv4(),
    },
    resolvers: {},
  },
  overviewLayoutCustomization: [
    { key: 'details', width: 6, label: 'Entity details' },
    { key: 'basicInformation', width: 6, label: 'Basic information' },
    { key: 'latestCreatedRelationships', width: 6, label: 'Latest created relationships' },
    { key: 'latestContainers', width: 6, label: 'Latest containers' },
    { key: 'externalReferences', width: 6, label: 'External references' },
    { key: 'mostRecentHistory', width: 6, label: 'Most recent history' },
    { key: 'notes', width: 12, label: 'Notes about this entity' },
  ],
  attributes: [
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'x_procedure_type', label: 'Procedure type', type: 'string', format: 'vocabulary', vocabularyCategory: 'procedure_type_ov', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'x_mitre_platforms', label: 'Platforms', type: 'string', format: 'vocabulary', vocabularyCategory: 'platforms_ov', mandatoryType: 'customizable', editDefault: true, multiple: true, upsert: true, isFilterable: true },
    { name: 'first_observed', label: 'First observed', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'last_observed', label: 'Last observed', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'x_execution_start', label: 'Execution start', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'x_execution_end', label: 'Execution end', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'x_fingerprint', label: 'Fingerprint', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    creators,
    createdAt,
    updatedAt,
  ],
  relations: [
    {
      name: RELATION_IMPLEMENTS_TECHNIQUE,
      targets: [
        { name: ENTITY_TYPE_ATTACK_PATTERN, type: REL_NEW },
      ],
    },
    {
      name: RELATION_USES,
      targets: [
        { name: ENTITY_TYPE_TOOL, type: REL_EXTENDED },
        { name: ENTITY_TYPE_MALWARE, type: REL_EXTENDED },
      ],
    },
    {
      name: RELATION_EXPLOITS,
      targets: [
        { name: ENTITY_TYPE_VULNERABILITY, type: REL_EXTENDED },
      ],
    },
    {
      name: RELATION_HAS_OBSERVABLE,
      targets: [
        { name: ABSTRACT_STIX_CYBER_OBSERVABLE, type: REL_NEW },
      ],
    },
  ],
  relationsRefs: [
    {
      name: INPUT_PROCEDURE_COMMAND,
      type: 'ref',
      databaseName: RELATION_PROCEDURE_COMMAND,
      stixName: ATTRIBUTE_COMMAND_REF,
      label: 'Command',
      mandatoryType: 'no',
      editDefault: false,
      multiple: false,
      upsert: true,
      isRefExistingForTypes(this, _, toType) {
        return this.toTypes.includes(toType);
      },
      isFilterable: true,
      toTypes: [ENTITY_PROCESS],
    },
    {
      name: INPUT_PROCEDURE_SOURCES,
      type: 'ref',
      databaseName: RELATION_PROCEDURE_SOURCE,
      stixName: ATTRIBUTE_SOURCE_REFS,
      label: 'Sources',
      mandatoryType: 'no',
      editDefault: false,
      multiple: true,
      upsert: true,
      isRefExistingForTypes(this, _, toType) {
        return isStixDomainObjectIdentity(toType);
      },
      isFilterable: true,
      toTypes: [ENTITY_TYPE_IDENTITY],
    },
    killChainPhases,
    objectLabel,
    objectMarking,
    createdBy,
    { ...objectOrganization, isFilterable: false },
  ],
  representative: (stix: StixProcedure) => {
    return stix.name;
  },
  converter_2_1: convertProcedureToStix,
};

registerDefinition(PROCEDURE_DEFINITION);
