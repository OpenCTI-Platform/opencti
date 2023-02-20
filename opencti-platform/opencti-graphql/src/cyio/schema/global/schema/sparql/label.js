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
    case 'LABEL':
      return labelReducer;
    default:
      throw new UserInputError(`Unsupported reducer type ' ${type}'`)
  }
}

//
// Reducers
//
const labelReducer = (item) => {
  // if no object type was returned, compute the type from the IRI
  if (item.object_type === undefined) {
    item.object_type = 'label';
  }

  return {
    id: item.id,
    standard_id: item.id,
    ...(item.object_type && { entity_type: item.object_type }),
    ...(item.created && { created: item.created }),
    ...(item.modified && { modified: item.modified }),
    ...(item.name && { name: item.name }),
    ...(item.description && { description: item.description }),
    // Label
    ...(item.color && { color: item.color }),
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
export const singularizeLabelSchema = { 
  singularizeVariables: {
    "": false, // so there is an object as the root instead of an array
    "id": true,
    "iri": true,
    "object_type": true,
    "entity_type": true,
    "created": true,
    "modified": true,
    "name": true,
    "description": true,
    "color": true,
  }
};
  