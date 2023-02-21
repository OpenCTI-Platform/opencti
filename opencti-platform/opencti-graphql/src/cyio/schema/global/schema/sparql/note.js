import { UserInputError } from 'apollo-server-errors';
import { 
  optionalizePredicate, 
  parameterizePredicate, 
  buildSelectVariables, 
  attachQuery,
  detachQuery,
  generateId, 
  DARKLIGHT_NS,
} from '../../../utils.js';
  
// Reducer Selection
export function getReducer(type) {
  switch (type) {
    case 'NOTE':
      return noteReducer;
    default:
      throw new UserInputError(`Unsupported reducer type ' ${type}'`)
  }
}

//
// Reducers
//
const noteReducer = (item) => {
  // if no object type was returned, compute the type from the IRI
  if (item.object_type === undefined) {
    item.object_type = 'note';
  }

  return {
    id: item.id,
    standard_id: item.id,
    ...(item.object_type && { entity_type: item.object_type }),
    ...(item.created && { created: item.created }),
    ...(item.modified && { modified: item.modified }),
    // Note
    ...(item.abstract && { abstract: item.abstract }),
    ...(item.content && { content: item.content }),
    ...(item.authors && { authors: item.authors }),
    // HINTS
    ...(item.labels && { labels_iri: item.labels }),
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
export const singularizeNoteSchema = { 
  singularizeVariables: {
    "": false, // so there is an object as the root instead of an array
    "id": true,
    "iri": true,
    "object_type": true,
    "entity_type": true,
    "created": true,
    "modified": true,
    "abstract": true,
    "content": true,
  }
};
  