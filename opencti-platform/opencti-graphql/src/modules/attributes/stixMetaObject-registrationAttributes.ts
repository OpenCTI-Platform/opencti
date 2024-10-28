import * as R from 'ramda';
import type { AttributeDefinition } from '../../schema/attribute-definition';
import { created, modified } from '../../schema/attribute-definition';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { ENTITY_TYPE_EXTERNAL_REFERENCE, ENTITY_TYPE_KILL_CHAIN_PHASE, ENTITY_TYPE_LABEL, ENTITY_TYPE_MARKING_DEFINITION } from '../../schema/stixMetaObject';
import { ABSTRACT_STIX_META_OBJECT } from '../../schema/general';

schemaAttributesDefinition.registerAttributes(ABSTRACT_STIX_META_OBJECT, [created, modified]);

const stixMetaObjectsAttributes: { [k: string]: Array<AttributeDefinition> } = {
  [ENTITY_TYPE_MARKING_DEFINITION]: [
    { name: 'definition_type', label: 'Marking type', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'definition', label: 'Definition', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'x_opencti_order', label: 'Marking order', type: 'numeric', precision: 'integer', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'x_opencti_color', label: 'Marking color', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  ],
  [ENTITY_TYPE_LABEL]: [
    { name: 'value', label: 'Value', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'color', label: 'Color', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: false, upsert: true, isFilterable: false },
  ],
  [ENTITY_TYPE_EXTERNAL_REFERENCE]: [
    { name: 'source_name', label: 'Source name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'url', label: 'URL', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'hash', label: 'Hash', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'fileId', label: 'File ID', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'external_id', label: 'External id', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  ],
  [ENTITY_TYPE_KILL_CHAIN_PHASE]: [
    { name: 'kill_chain_name', label: 'Kill chain name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'phase_name', label: 'Phase name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'x_opencti_order', label: 'Kill chain order', type: 'numeric', precision: 'integer', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: true },
  ],
};
R.forEachObjIndexed((value, key) => schemaAttributesDefinition.registerAttributes(key as string, value), stixMetaObjectsAttributes);
