import * as R from 'ramda';
import type { AttributeDefinition } from '../../schema/attribute-definition';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { RELATION_ALLOWED_BY, RELATION_PARTICIPATE_TO } from '../../schema/internalRelationship';

export const internalRelationshipsAttributes: { [k: string]: Array<AttributeDefinition> } = {
  [RELATION_PARTICIPATE_TO]: [
    { name: 'start_time', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'stop_time', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'confidence', type: 'numeric', mandatoryType: 'no', multiple: false, upsert: false },
  ],
  [RELATION_ALLOWED_BY]: [
    { name: 'grant', type: 'string', mandatoryType: 'no', multiple: true, upsert: false }
  ],
};
R.forEachObjIndexed((value, key) => schemaAttributesDefinition.registerAttributes(key as string, value), internalRelationshipsAttributes);
