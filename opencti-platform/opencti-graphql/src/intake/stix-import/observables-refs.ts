import type { ImportContext } from './context';
import { kw, type Kwargs } from './kwargs';

// pycti/entities/opencti_stix_nested_ref_relationship.py
const STIX_REF_RELATIONSHIP_ADD = `
  mutation StixRefRelationshipAdd($input: StixRefRelationshipAddInput!) {
    stixRefRelationshipAdd(input: $input) { id standard_id entity_type parent_types }
  }
`;

const RELATIONSHIP_TYPE_RENAMES = new Map([
  ['resolves-to', 'obs_resolves-to'],
  ['belongs-to', 'obs_belongs-to'],
  ['content', 'obs_content'],
]);

// pycti stix_nested_ref_relationship.create
export const createStixNestedRefRelationship = async (context: ImportContext, kwargs: Kwargs) => {
  let relationshipType = kw(kwargs, 'relationship_type') as string | null;
  if (relationshipType !== null && RELATIONSHIP_TYPE_RENAMES.has(relationshipType)) {
    relationshipType = RELATIONSHIP_TYPE_RENAMES.get(relationshipType) as string;
  }
  const data = await context.client.query(STIX_REF_RELATIONSHIP_ADD, {
    input: {
      fromId: kw(kwargs, 'fromId'),
      toId: kw(kwargs, 'toId'),
      relationship_type: relationshipType,
      start_time: kw(kwargs, 'start_time'),
      stop_time: kw(kwargs, 'stop_time'),
      stix_id: kw(kwargs, 'stix_id'),
      created: kw(kwargs, 'created'),
      modified: kw(kwargs, 'modified'),
      createdBy: kw(kwargs, 'createdBy'),
      objectMarking: kw(kwargs, 'objectMarking'),
      x_opencti_stix_ids: kw(kwargs, 'x_opencti_stix_ids'),
      update: kw(kwargs, 'update', false),
    },
  });
  return data.stixRefRelationshipAdd;
};
