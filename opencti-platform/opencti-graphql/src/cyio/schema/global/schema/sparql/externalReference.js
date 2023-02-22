import { UserInputError } from 'apollo-server-errors';
import { 
  optionalizePredicate, 
  parameterizePredicate, 
  buildSelectVariables, 
  attachQuery,
  detachQuery,
  generateId, 
  DARKLIGHT_NS,
} from '../../../utils.js'
  
// Reducer Selection
export function getReducer(type) {
  switch (type) {
    case 'EXTERNAL-REFERENCE':
      return externalReferenceReducer;
    default:
      throw new UserInputError(`Unsupported reducer type ' ${type}'`)
  }
}
    
//
// Reducers
//
const externalReferenceReducer = (item) => {
  // if no object type was returned, compute the type from the IRI
  if (item.object_type === undefined) {
    item.object_type = 'external-reference';
  }

  return {
    id: item.id,
    standard_id: item.id,
    ...(item.object_type && { entity_type: item.object_type }),
    ...(item.created && { created: item.created }),
    ...(item.modified && { modified: item.modified }),
    // External Reference
    ...(item.source_name && { source_name: item.source_name }),
    ...(item.description && { description: item.description }),
    ...(item.url && { url: item.url }),
    ...(item.external_id && { external_id: item.external_id }),
    // OSCAL Link
    ...(item.reference_purpose && { reference_purpose: item.reference_purpose }),
    ...(item.media_type && { media_type: item.media_type }),
    ...(item.label_text && { label_text: item.label_text }),
    // HINTS
    ...(item.hashes && { hashes_iri: item.hashes }),
  };
};


//
// Query Builder Functions
//


//
// Predicate Map
//



//
// Serialization schema
//
export const singularizeExternalReferenceSchema = { 
  singularizeVariables: {
    "": false, // so there is an object as the root instead of an array
    "id": true,
    "iri": true,
    "object_type": true,
    "entity_type": true,
    "created": true,
    "modified": true,
    "source_name": true,
    "description": true,
    "url": true,
    "external_id": true,
  }
};
  