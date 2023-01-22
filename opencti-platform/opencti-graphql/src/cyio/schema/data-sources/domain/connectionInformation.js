import { UserInputError } from 'apollo-server-express';
import { compareValues, filterValues, updateQuery, checkIfValidUUID, validateEnumValue, CyioError } from '../../utils.js';
import {
  getReducer,
  connectionInformationPredicateMap,
  singularizeSchema,
  deleteConnectionInformationQuery,
  insertConnectionInformationQuery,
  selectAllConnectionInformationQuery,
  selectConnectionInformationQuery,
  selectConnectionInformationByIriQuery,
} from '../schema/sparql/connectionInformation.js';

export const findConnectionConfigById = async (connectionId, dbName, dataSources, selectMap) => {
  // ensure the id is a valid UUID
  if (!checkIfValidUUID(connectionId)) throw new CyioError(`Invalid identifier: ${connectionId}`);  

  let iri = `<http://cyio.darklight.ai/connection-information--${connectionId}>`;
  return findConnectionConfigByIri(iri, dbName, dataSources, selectMap);
}

export const findConnectionConfigByIri = async (connectionIri, dbName, dataSources, selectMap) => {
  const sparqlQuery = selectConnectionInformationByIriQuery(connectionIri, selectMap.getNode("connectionConfig"));
  let response;
  try {
    response = await dataSources.Stardog.queryById({
      dbName: 'cyio-config',
      sparqlQuery,
      queryId: "Select Configuration Information",
      singularizeSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }

  if (response === undefined) return null;
  if (typeof (response) === 'object' && 'body' in response) {
    throw new UserInputError(response.statusText, {
      error_details: (response.body.message ? response.body.message : response.body),
      error_code: (response.body.code ? response.body.code : 'N/A')
    });
  }

  if (Array.isArray(response) && response.length > 0) {
    const reducer = getReducer("CONNECTION-INFORMATION");
    return reducer(response[0]);  
  }
};

export const findAllConnectionConfig = async (args, dbName, dataSources, selectMap) => {
  const sparqlQuery = selectAllConnectionInformationQuery(selectMap.getNode("node"), args);
  let response;
  try {
    response = await dataSources.Stardog.queryAll({
      dbName: 'cyio-config',
      sparqlQuery,
      queryId: "Select List of Configuration Information",
      singularizeSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }

  // no results found
  if (response === undefined || response.length === 0) return null;

  // Handle reporting Stardog Error
  if (typeof (response) === 'object' && 'body' in response) {
    throw new UserInputError(response.statusText, {
      error_details: (response.body.message ? response.body.message : response.body),
      error_code: (response.body.code ? response.body.code : 'N/A')
    });
  }

  // if no matching results, then return null
  if (Array.isArray(response) && response.length < 1) return null;

  const edges = [];
  const reducer = getReducer("CONNECTION-INFORMATION");
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

export const createConnectionConfig = async (input, dbName, selectMap, dataSources) => {
  // TODO: WORKAROUND to remove input fields with null or empty values so creation will work
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

  // create the Connection Information object
  let response;
  let {iri, id:connectionId, query} = insertConnectionInformationQuery(input);
  try {
    response = await dataSources.Stardog.create({
      dbName: 'cyio-config',
      sparqlQuery: query,
      queryId: "Create Connection Information object"
      });
  } catch (e) {
    console.log(e)
    throw e
  }

  // retrieve the newly created Connection Information to be returned
  const select = selectConnectionInformationQuery(connectionId, selectMap.getNode("createConnectionConfig"));
  const result = await dataSources.Stardog.queryById({
    dbName: 'cyio-config',
    sparqlQuery: select,
    queryId: "Select Connection Information object",
    singularizeSchema
  });
  const reducer = getReducer("CONNECTION-INFORMATION");
  return reducer(result[0]);
};

export const deleteConnectionConfigById = async (connectionId, dbName, dataSources) => {  
  let select = ['id','object_type'];
  if (!Array.isArray(connectionId)) {
    if (!checkIfValidUUID(connectionId)) throw new CyioError(`Invalid identifier: ${connectionId}`);

    // check if object with id exists
    let sparqlQuery = selectConnectionInformationQuery(connectionId, select);
    let response;
    try {
      response = await dataSources.Stardog.queryById({
        dbName: 'cyio-config',
        sparqlQuery,
        queryId: "Select Connection Information",
        singularizeSchema
      });
    } catch (e) {
      console.log(e)
      throw e
    }
    if (response === undefined || response.length === 0) throw new CyioError(`Entity does not exist with ID ${id}`);

    // delete the object
    sparqlQuery = deleteConnectionInformationQuery(connectionId);
    try {
      response = await dataSources.Stardog.delete({
        dbName: 'cyio-config',
        sparqlQuery,
        queryId: "Delete Connection Information"
      });
    } catch (e) {
      console.log(e)
      throw e
    }
    
    return connectionId;
  } 

  if (Array.isArray(connectionId)) {
    let removedIds = []
    for (let itemId of connectionId) {
      let response;
      if (!checkIfValidUUID(itemId)) throw new CyioError(`Invalid identifier: ${itemId}`);  

      // check if object with id exists
      let sparqlQuery = selectConnectionInformationQuery(itemId, select);
      try {
        response = await dataSources.Stardog.queryById({
          dbName: 'cyio-config',
          sparqlQuery,
          queryId: "Select Connection Information",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }
      
      if (response === undefined || response.length === 0) throw new CyioError(`Entity does not exist with ID ${itemId}`);

      sparqlQuery = deleteConnectionInformationQuery(itemId);
      try {
        response = await dataSources.Stardog.delete({
          dbName: 'cyio-config',
          sparqlQuery,
          queryId: "Delete Connection Information"
        });
      } catch (e) {
        console.log(e)
        throw e
      }
      
      removedIds.push(itemId);
    }

    return removedIds;
  }
};

export const editConnectionConfigById = async (connectionId, input, dbName, dataSources, selectMap, schema) => {
  // make sure there is input data containing what is to be edited
  if (input === undefined || input.length === 0) throw new CyioError(`No input data was supplied`);

  // WORKAROUND to remove immutable fields
  input = input.filter(element => (element.key !== 'id' && element.key !== 'created' && element.key !== 'modified'));

  // check that the object to be edited exists with the predicates - only get the minimum of data
  let editSelect = ['id','created','modified'];
  for (let editItem of input) {
    editSelect.push(editItem.key);
  }

  const sparqlQuery = selectConnectionInformationQuery(connectionId, editSelect );
  let response = await dataSources.Stardog.queryById({
    dbName: 'cyio-config',
    sparqlQuery,
    queryId: "Select Connection Information",
    singularizeSchema
  });
  if (response.length === 0) throw new CyioError(`Entity does not exist with ID ${connectionId}`);

  // determine operation, if missing
  for (let editItem of input) {
    if (editItem.operation !== undefined) continue;

    // if value if empty then treat as a remove
    if (editItem.value.length === 0) {
      editItem.operation = 'remove';
      continue;
    }
    if (Array.isArray(editItem.value) && editItem.value[0] === null) throw new CyioError(`Field "${editItem.key}" has invalid value "null"`);

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
        case 'connector_type':
          if (!validateEnumValue(value, 'ConnectorType', schema)) throw new CyioError(`Invalid value "${value}" for field "${editItem.key}".`);
          editItem.value[0] = value.replace(/_/g,'-').toLowerCase();
          fieldType = 'simple';
          break;
        case 'http_request_method':
          if (!validateEnumValue(value, 'HttpRequestMethod', schema)) throw new CyioError(`Invalid value "${value}" for field "${editItem.key}".`);
          fieldType = 'simple';
          break;
        default:
          fieldType = 'simple';
          break;
      }

      if (fieldType === 'id') {
        // continue to next item if nothing to do
        if (editItem.operation === 'skip') continue;

        let iri = `${objectMap[objectType].iriTemplate}-${value}`;
        let sparqlQuery = selectObjectIriByIdQuery(value, objectType);
        let result = await dataSources.Stardog.queryById({
          dbName: 'cyio-config',
          sparqlQuery,
          queryId: "Obtaining IRI for the object with id",
          singularizeSchema
        });
        if (result === undefined || result.length === 0) throw new CyioError(`Entity does not exist with ID ${value}`);
        iris.push(`<${result[0].iri}>`);
      }
    }
    if (iris.length > 0) editItem.value = iris;
  }    

  const query = updateQuery(
    `http://cyio.darklight.ai/connection-information--${connectionId}`,
    "http://darklight.ai/ns/cyio/connection#ConnectionInformation",
    input,
    connectionInformationPredicateMap
  );
  if (query !== null) {
    let response;
    try {
      response = await dataSources.Stardog.edit({
        dbName: 'cyio-config',
        sparqlQuery: query,
        queryId: "Update Connection Information"
      });  
    } catch (e) {
      console.log(e)
      throw e
    }

    if (response !== undefined && 'status' in response) {
      if (response.ok === false || response.status > 299) {
        // Handle reporting Stardog Error
        throw new UserInputError(response.statusText, {
          error_details: (response.body.message ? response.body.message : response.body),
          error_code: (response.body.code ? response.body.code : 'N/A')
        });
      }
    }
  }

  const select = selectConnectionInformationQuery(connectionId, selectMap.getNode("editConnectionConfig"));
  const result = await dataSources.Stardog.queryById({
    dbName: 'cyio-config',
    sparqlQuery: select,
    queryId: "Select Connection Information",
    singularizeSchema
  });
  const reducer = getReducer("CONNECTION-INFORMATION");
  return reducer(result[0]);
};

