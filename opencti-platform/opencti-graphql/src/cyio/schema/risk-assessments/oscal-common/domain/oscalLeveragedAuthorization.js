import { UserInputError } from 'apollo-server-errors';
import { compareValues, filterValues, updateQuery, checkIfValidUUID, validateEnumValue } from '../../utils.js';
import { selectObjectIriByIdQuery } from '../../global/global-utils.js';
import {
  getReducer,
	// OSCAL User
  oscalLeveragedAuthorizationPredicateMap,
  singularizeOscalLeveragedAuthorizationSchema,
  selectOscalLeveragedAuthorizationQuery,
  selectOscalLeveragedAuthorizationByIriQuery,
  selectAllOscalLeveragedAuthorizationsQuery,
  insertOscalLeveragedAuthorizationQuery,
  deleteOscalLeveragedAuthorizationQuery,
  deleteOscalLeveragedAuthorizationByIriQuery,
  attachToOscalLeveragedAuthorizationQuery,
  detachFromOscalLeveragedAuthorizationQuery,
} from '../schema/sparql/oscalLeveragedAuthorization.js';


// OSCAL Leveraged Authorization
export const findLeveragedAuthorizationById = async (id, dbName, dataSources, select) => {
  // ensure the id is a valid UUID
  if (!checkIfValidUUID(id)) throw new UserInputError(`Invalid identifier: ${id}`);

  let iri = `<http://cyio.darklight.ai/oscal-leveraged-authorization--${id}>`;
  return findLeveragedAuthorizationByIri(iri, dbName, dataSources, select);
}

export const findLeveragedAuthorizationByIri = async (iri, dbName, dataSources, select) => {
  const sparqlQuery = selectOscalLeveragedAuthorizationByIriQuery(iri, select);
  let response;
  try {
    response = await dataSources.Stardog.queryById({
      dbName,
      sparqlQuery,
      queryId: "Select OSCAL Leveraged Authorization",
      singularizeSchema: singularizeOscalLeveragedAuthorizationSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }
  if (response === undefined || response === null || response.length === 0) return null;
  const reducer = getReducer("OSCAL-LEVERAGED-AUTHORIZATION");
  return reducer(response[0]);  
};

export const findAllLeveragedAuthorizations = async (args, dbName, dataSources, select ) => {
  const sparqlQuery = selectAllOscalLeveragedAuthorizationsQuery(select, args);
  let response;
  try {
    response = await dataSources.Stardog.queryAll({
      dbName,
      sparqlQuery,
      queryId: "Select List of OSCAL Leveraged Authorization types",
      singularizeSchema: singularizeOscalLeveragedAuthorizationSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }

  // no results found
  if (response === undefined || response.length === 0) return null;

  // if no matching results, then return null
  if (Array.isArray(response) && response.length < 1) return null;

  const edges = [];
  const reducer = getReducer("OSCAL-LEVERAGED-AUTHORIZATION");
  let skipCount = 0,filterCount = 0, resultCount = 0, limit, offset, limitSize, offsetSize;
  limitSize = limit = (args.first === undefined ? response.length : args.first) ;
  offsetSize = offset = (args.offset === undefined ? 0 : args.offset) ;

  let resultList ;
  if (args.orderedBy !== undefined ) {
    resultList = response.sort(compareValues(args.orderedBy, args.orderMode ));
  } else {
    resultList = response;
  }

  // return null if offset value beyond number of results items
  if (offset > resultList.length) return null;

  // for each result in the result set
  for (let resultItem of resultList) {
    // skip down past the offset
    if (offset) {
      offset--
      continue
    }

    // filter out non-matching entries if a filter is to be applied
    if ('filters' in args && args.filters != null && args.filters.length > 0) {
      if (!filterValues(resultItem, args.filters, args.filterMode) ) {
        continue
      }
      filterCount++;
    }

    // if haven't reached limit to be returned
    if (limit) {
      let edge = {
        cursor: resultItem.iri,
        node: reducer(resultItem),
      }
      edges.push(edge)
      limit--;
      if (limit === 0) break;
    }
  }
  // check if there is data to be returned
  if (edges.length === 0 ) return null;
  let hasNextPage = false, hasPreviousPage = false;
  resultCount = resultList.length - skipCount;
  if (edges.length < resultCount) {
    if (edges.length === limitSize && filterCount <= limitSize ) {
      hasNextPage = true;
      if (offsetSize > 0) hasPreviousPage = true;
    }
    if (edges.length <= limitSize) {
      if (filterCount !== edges.length) hasNextPage = true;
      if (filterCount > 0 && offsetSize > 0) hasPreviousPage = true;
    }
  }
  return {
    pageInfo: {
      startCursor: edges[0].cursor,
      endCursor: edges[edges.length-1].cursor,
      hasNextPage: (hasNextPage ),
      hasPreviousPage: (hasPreviousPage),
      globalCount: resultCount,
    },
    edges: edges,
  }
};

export const createLeveragedAuthorization = async (input, dbName, dataSources, select) => {
  // WORKAROUND to remove input fields with null or empty values so creation will work
  for (const [key, value] of Object.entries(input)) {
    if (Array.isArray(input[key]) && input[key].length === 0) {
      delete input[key];
      continue;
    }
    if (value === null || value.length === 0) {
      delete input[key];
    }
  }
  // END WORKAROUND

  // Need to escape contents, remove explicit newlines, and collapse multiple what spaces.
  if (input.title !== undefined ) {
    input.name = input.name.replace(/\s+/g, ' ')
                            .replace(/\n/g, '\\n')
                            .replace(/\"/g, '\\"')
                            .replace(/\'/g, "\\'")
                            .replace(/[\u2019\u2019]/g, "\\'")
                            .replace(/[\u201C\u201D]/g, '\\"');
  }

  // Collect all the referenced objects and remove them from input array
  let objectReferences = {
    'party': { ids: input.party, objectType: 'oscal-party' },
  };
  if (input.party) delete input.party;
  
  // create the OSCAL Leveraged Authorization
  let response;
  let {iri, id, query} = insertOscalLeveragedAuthorizationQuery(input);
  try {
    response = await dataSources.Stardog.create({
      dbName,
      sparqlQuery: query,
      queryId: "Create OSCAL Leveraged Authorization"
      });
  } catch (e) {
    console.log(e)
    throw e
  }

  // Attach any references to other objects
  for (let [key, value] of Object.entries(objectReferences)) {
    if (value.ids === undefined || value.ids === null) continue;
        let itemName = value.objectType.replace(/-/g, ' ');
    let iris = [];
    for (let refId of value.ids) {
      let sparqlQuery = selectObjectIriByIdQuery(refId, value.objectType);
      let result = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery,
        queryId: "Obtaining IRI for the object with id",
        singularizeSchema: singularizeOscalLeveragedAuthorizationSchema
      });
      if (result === undefined || result.length === 0) throw new UserInputError(`Entity does not exist with ID ${refId}`);
      iris.push(`<${result[0].iri}>`);
    }

    if (iris.length > 0) {
      // attach the definition to the new Information Type
      let attachQuery = attachToOscalLeveragedAuthorizationQuery(id, key, iris );
      try {
        response = await dataSources.Stardog.create({
          dbName,
          sparqlQuery: attachQuery,
          queryId: `Attaching one or more ${itemName} to OSCAL Leveraged Authorization`
          });
      } catch (e) {
        console.log(e)
        throw e
      }
    }
  }

  // retrieve the newly created OSCAL Leveraged Authorization to be returned
  const selectQuery = selectOscalLeveragedAuthorizationQuery(id, select);
  let result;
  try {
    result = await dataSources.Stardog.queryById({
      dbName,
      sparqlQuery: selectQuery,
      queryId: "Select OSCAL Leveraged Authorization object",
      singularizeSchema: singularizeOscalLeveragedAuthorizationSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }
  if (result === undefined || result === null || result.length === 0) return null;
  const reducer = getReducer("OSCAL-LEVERAGED-AUTHORIZATION");
  return reducer(result[0]);
};

export const deleteLeveragedAuthorizationById = async ( id, dbName, dataSources ) => {
  let select = ['iri','id','object_type','party'];
  let idArray = [];
  if (!Array.isArray(id)) {
    idArray = [id];
  } else {
    idArray = id;
  }

  let removedIds = []
  for (let itemId of idArray) {
    let response;
    if (!checkIfValidUUID(itemId)) throw new UserInputError(`Invalid identifier: ${itemId}`);  

    // check if object with id exists
    let sparqlQuery = selectOscalLeveragedAuthorizationQuery(itemId, select);
    try {
      response = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery,
        queryId: "Select OSCAL Leveraged Authorization",
        singularizeSchema: singularizeOscalLeveragedAuthorizationSchema
      });
    } catch (e) {
      console.log(e)
      throw e
    }
    if (response === undefined || response.length === 0) throw new UserInputError(`Entity does not exist with ID ${itemId}`);

    sparqlQuery = deleteOscalLeveragedAuthorizationQuery(itemId);
    try {
      response = await dataSources.Stardog.delete({
        dbName,
        sparqlQuery,
        queryId: "Delete OSCAL Leveraged Authorization"
      });
    } catch (e) {
      console.log(e)
      throw e
    }
    
    removedIds.push(itemId);
  }

  if (!Array.isArray(id)) return id;
  return removedIds;
};

export const editLeveragedAuthorizationById = async ( id, input, dbName, dataSources, select, schema ) => {
  if (!checkIfValidUUID(id)) throw new UserInputError(`Invalid identifier: ${id}`);  

  // make sure there is input data containing what is to be edited
  if (input === undefined || input.length === 0) throw new UserInputError(`No input data was supplied`);

  // WORKAROUND to remove immutable fields
  input = input.filter(element => (element.key !== 'id' && element.key !== 'created' && element.key !== 'modified'));

  // check that the object to be edited exists with the predicates - only get the minimum of data
  let editSelect = ['id','created','modified'];
  for (let editItem of input) {
    editSelect.push(editItem.key);
  }

  const sparqlQuery = selectOscalLeveragedAuthorizationQuery(id, editSelect );
  let response = await dataSources.Stardog.queryById({
    dbName,
    sparqlQuery,
    queryId: "Select OSCAL Leveraged Authorization",
    singularizeSchema: singularizeOscalLeveragedAuthorizationSchema
  });
  if (response.length === 0) throw new UserInputError(`Entity does not exist with ID ${id}`);

  // determine operation, if missing
  for (let editItem of input) {
    if (editItem.operation !== undefined) continue;

    // if value if empty then treat as a remove
    if (editItem.value.length === 0) {
      editItem.operation = 'remove';
      continue;
    }
    if (Array.isArray(editItem.value) && editItem.value[0] === null) throw new UserInputError(`Field "${editItem.key}" has invalid value "null"`);

    if (!response[0].hasOwnProperty(editItem.key)) {
      editItem.operation = 'add';
    } else {
      editItem.operation = 'replace';

      // Set operation to 'skip' if no change in value
      if (response[0][editItem.key] === editItem.value) editItem.operation ='skip';
    }
  }

  // Push an edit to update the modified time of the object
  const timestamp = new Date().toISOString();
  if (!response[0].hasOwnProperty('created')) {
    let update = {key: "created", value:[`${timestamp}`], operation: "add"}
    input.push(update);
  }
  let operation = "replace";
  if (!response[0].hasOwnProperty('modified')) operation = "add";
  let update = {key: "modified", value:[`${timestamp}`], operation: `${operation}`}
  input.push(update);

  // Handle the update to fields that have references to other object instances
  for (let editItem  of input) {
    if (editItem.operation === 'skip') continue;

    let value, fieldType, objectType, objArray, iris=[];
    for (value of editItem.value) {
      switch(editItem.key) {
        case 'party':
          objectType = 'oscal-party';
          fieldType = 'id';
          break;
      case 'labels':
          objectType = 'label';
          fieldType = 'id';
          break;
      case 'links':
          objectType = 'external-reference';
          fieldType = 'id';
          break;
        case 'remarks':
          objectType = 'note';
          fieldType = 'id';
          break;
        default:
          fieldType = 'simple';
          break;
      }

      if (fieldType === 'id') {
        // continue to next item if nothing to do
        if (editItem.operation === 'skip') continue;

        let sparqlQuery = selectObjectIriByIdQuery(value, objectType);
        let result = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: "Obtaining IRI for the object with id",
          singularizeSchema: singularizeOscalLeveragedAuthorizationSchema
        });
        if (result === undefined || result.length === 0) throw new UserInputError(`Entity does not exist with ID ${value}`);
        iris.push(`<${result[0].iri}>`);
      }
    }
    if (iris.length > 0) editItem.value = iris;
  }    

  const query = updateQuery(
    `http://cyio.darklight.ai/oscal-leveraged-authorization--${id}`,
    "http://csrc.nist.gov/ns/oscal/common#LeveragedAuthorization",
    input,
    oscalLeveragedAuthorizationPredicateMap
  );
  if (query !== null) {
    let response;
    try {
      response = await dataSources.Stardog.edit({
        dbName,
        sparqlQuery: query,
        queryId: "Update OSCAL Leveraged Authorization"
      });  
    } catch (e) {
      console.log(e)
      throw e
    }
  }

  const selectQuery = selectOscalLeveragedAuthorizationQuery(id, select);
  const result = await dataSources.Stardog.queryById({
    dbName,
    sparqlQuery: selectQuery,
    queryId: "Select OSCAL Leveraged Authorization",
    singularizeSchema: singularizeOscalLeveragedAuthorizationSchema
  });
  const reducer = getReducer("OSCAL-LEVERAGED-AUTHORIZATION");
  return reducer(result[0]);
};

export const attachToLeveragedAuthorization = async ( id, field, entityId, dbName, dataSources ) => {
  let sparqlQuery;
  if (!checkIfValidUUID(id)) throw new UserInputError(`Invalid identifier: ${id}`);
  if (!checkIfValidUUID(entityId)) throw new UserInputError(`Invalid identifier: ${entityId}`);

  // check to see if the information system exists
  let iri = `<http://cyio.darklight.ai/oscal-leveraged-authorization--${id}>`;
  sparqlQuery = selectOscalLeveragedAuthorizationByIriQuery(iri, select);
  let response;
  try {
    response = await dataSources.Stardog.queryById({
      dbName,
      sparqlQuery,
      queryId: "Select OSCAL Leveraged Authorization",
      singularizeSchema: singularizeOscalLeveragedAuthorizationSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }
  if (response === undefined || response === null || response.length === 0) throw new UserInputError(`Entity does not exist with ID ${id}`);

  let attachableObjects = {
    'party': 'oscal-party',
    'labels': 'label',
    'links': 'link',
    'remarks': 'remark'
  }
  let objectType = attachableObjects[field];
  try {
    // check to see if the entity exists
    sparqlQuery = selectObjectIriByIdQuery(entityId, objectType);
    response = await dataSources.Stardog.queryById({
      dbName,
      sparqlQuery,
      queryId: "Obtaining IRI for the object with id",
      singularizeSchema: singularizeOscalLeveragedAuthorizationSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }
  if (response === undefined || response === null || response.length === 0) throw new UserInputError(`Entity does not exist with ID ${id}`);
  
  // check to make sure entity to be attached is proper for the field specified
  if (response[0].object_type !== attachableObjects[field]) throw new UserInputError(`Can not attach object of type '${response[0].object_type}' to field '${field}'`);

  // retrieve the IRI of the entity
  let entityIri = `<${response[0].iri}>`;

  // Attach the object to the information system
  sparqlQuery = attachToOscalLeveragedAuthorizationQuery(id, field, entityIri);
  try {
    response = await dataSources.Stardog.create({
      dbName,
      sparqlQuery,
      queryId: `Attach ${field} to OSCAL Leveraged Authorization`
      });
  } catch (e) {
    console.log(e)
    throw e
  }

  return true;
};

export const detachFromLeveragedAuthorization = async ( id, field, entityId, dbName, dataSources ) => {
  let sparqlQuery;
  if (!checkIfValidUUID(id)) throw new UserInputError(`Invalid identifier: ${id}`);
  if (!checkIfValidUUID(entityId)) throw new UserInputError(`Invalid identifier: ${entityId}`);

  // check to see if the information system exists
  let iri = `<http://cyio.darklight.ai/oscal-leveraged-authorization--${id}>`;
  sparqlQuery = selectOscalLeveragedAuthorizationByIriQuery(iri, select);
  let response;
  try {
    response = await dataSources.Stardog.queryById({
      dbName,
      sparqlQuery,
      queryId: "Select OSCAL Leveraged Authorization",
      singularizeSchema: singularizeOscalLeveragedAuthorizationSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }
  if (response === undefined || response === null || response.length === 0) throw new UserInputError(`Entity does not exist with ID ${id}`);

  let attachableObjects = {
    'party': 'oscal-party',
    'labels': 'label',
    'links': 'link',
    'remarks': 'remark'
  }
  let objectType = attachableObjects[field];
  try {
    // check to see if the entity exists
    sparqlQuery = selectObjectIriByIdQuery(entityId, objectType);
    response = await dataSources.Stardog.queryById({
      dbName,
      sparqlQuery,
      queryId: "Obtaining IRI for the object with id",
      singularizeSchema: singularizeOscalLeveragedAuthorizationSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }
  if (response === undefined || response === null || response.length === 0) throw new UserInputError(`Entity does not exist with ID ${id}`);

  // check to make sure entity to be attached is proper for the field specified
  if (response[0].object_type !== attachableObjects[field]) throw new UserInputError(`Can not attach object of type '${response[0].object_type}' to field '${field}'`);

  // retrieve the IRI of the entity
  let entityIri = `<${response[0].iri}>`;

  // Attach the object to the information system
  sparqlQuery = detachFromOscalLeveragedAuthorizationQuery(id, field, entityIri);
  try {
    response = await dataSources.Stardog.create({
      dbName,
      sparqlQuery,
      queryId: `Detach ${field} from OSCAL Leveraged Authorization`
      });
  } catch (e) {
    console.log(e)
    throw e
  }

  return true;
};
