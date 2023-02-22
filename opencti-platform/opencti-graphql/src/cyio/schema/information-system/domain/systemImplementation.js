import { UserInputError } from 'apollo-server-errors';
import { compareValues, filterValues, updateQuery, checkIfValidUUID, validateEnumValue, CyioError } from '../../utils.js';
import conf from '../../../../config/conf';
import { selectObjectIriByIdQuery } from '../../global/global-utils.js';
import {
  getReducer,
  systemImplementationPredicateMap,
  singularizeSystemImplementationSchema,
  selectSystemImplementationQuery,
  selectSystemImplementationByIriQuery,
  selectAllSystemImplementationsQuery,
  insertSystemImplementationQuery,
  deleteSystemImplementationQuery,
  attachToSystemImplementationQuery,
  detachFromSystemImplementationQuery,
} from '../schema/sparql/systemImplementation.js';


// System Implementation
export const findSystemImplementationById = async (id, dbName, dataSources, select) => {
  // ensure the id is a valid UUID
  if (!checkIfValidUUID(id)) throw new CyioError(`Invalid identifier: ${id}`);

  let iri = `<http://cyio.darklight.ai/system-implementation--${id}>`;
  return findSystemImplementationByIri(iri, dbName, dataSources, select);
}

export const findSystemImplementationByIri = async (iri, dbName, dataSources, select) => {
  const sparqlQuery = selectSystemImplementationByIriQuery(iri, select);
  let response;
  try {
    response = await dataSources.Stardog.queryById({
      dbName: dbName,
      sparqlQuery,
      queryId: "Select System Implementation",
      singularizeSchema: singularizeSystemImplementationSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }

  if (response === undefined || response === null || response.length === 0) return null;
  const reducer = getReducer("SYSTEM-IMPLEMENTATION");
  return reducer(response[0]);  
};

export const findAllInformationTypeEntries = async (args, dbName, dataSources, select ) => {
  const sparqlQuery = selectAllSystemImplementationsQuery(select, args);
  let response;
  try {
    response = await dataSources.Stardog.queryAll({
      dbName: dbName,
      sparqlQuery,
      queryId: "Select List of System Implementations",
      singularizeSchema: singularizeSystemImplementationSchema
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
  const reducer = getReducer("SYSTEM-IMPLEMENTATION");
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

export const createSystemImplementation = async (input, dbName, dataSources, selectMap) => {
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

  // Collect all the nested definitions and remove them from input array
  let nestedDefinitions = {
    'information-types': { props: {}, field: 'information_types'},
    'responsible-parties': { props: {}, field: 'responsible_parties'},
    'system-implementation': { props: {}, field: 'system_implementation'},
    'authorization_boundary': { props: {}, field: 'authorization_boundary'},
    'network_architecture': { props: {}, field: 'network_architecture'},
    'data-flow': {props: {}, field: 'data_flow'}
  };
  for (let item of nestedDefinitions) {
    let itemName = input[item.field];
    for ( let [key, value] of Object.entries(itemName)) {
      itemName.props[key] = value.replace(/\s+/g, ' ')
                                  .replace(/\n/g, '\\n')
                                  .replace(/\"/g, '\\"')
                                  .replace(/\'/g, "\\'")
                                  .replace(/[\u2019\u2019]/g, "\\'")
                                  .replace(/[\u201C\u201D]/g, '\\"');
    }
    delete input[itemName];
  }

  // create the System Implementation object
  let response;
  let {iri, id, query} = insertSystemImplementationQuery(input);
  try {
    response = await dataSources.Stardog.create({
      dbName: dbName,
      sparqlQuery: query,
      queryId: "Create System Implementation object"
      });
  } catch (e) {
    console.log(e)
    throw e
  }

  // Attach any impact definitions
  for (let [key, value] of Object.entries(nestedDefinitions)) {
    // Create the nested Definition
    let itemName = key;
    let insertFunction;
    switch(key) {
      case 'information-types':
        insertFunction = insertInformationTypeQuery;
        break;
      case 'responsible-parties':
        insertFunction = insertResponsiblePartyQuery;
        break;
      case 'system-implementation':
        insertFunction = insertSystemImplementationQuery;
        break;
      case 'authorization-boundary':
      case 'network-architecture':
      case 'data-flow':
        insertFunction = insertDescriptionBlockQuery;
        break;
      default:
        break;
    }
    if (Object.keys(value.props).length !== 0 ) {
      let {iri: itemIri, id: itemId, query} = insertFunction(value.props);
      try {
        // Create Impact Definition
        response = await dataSources.Stardog.create({
          dbName: dbName,
          sparqlQuery: query,
          queryId: `Create ${itemName}`
          });
      } catch (e) {
        console.log(e)
        throw e
      }

      // attach the definition to the new System Implementation
      let attachQuery = attachToSystemImplementationQuery(id, value.field, itemIri );
      try {
        response = await dataSources.Stardog.create({
          dbName: dbName,
          sparqlQuery: attachQuery,
          queryId: `Attach ${itemName}`
          });
      } catch (e) {
        console.log(e)
        throw e
      }
    }
  }

  // retrieve the newly created System Implementation to be returned
  const selectQuery = selectSystemImplementationQuery(id, selectMap.getNode("createSystemImplementation"));
  let result;
  try {
    result = await dataSources.Stardog.queryById({
      dbName: dbName,
      sparqlQuery: selectQuery,
      queryId: "Select System Implementation object",
      singularizeSchema: singularizeSystemImplementationSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }
  if (result === undefined || result === null || result.length === 0) return null;
  const reducer = getReducer("SYSTEM-IMPLEMENTATION");
  return reducer(result[0]);
};

export const deleteSystemImplementationById = async ( id, catalogId, dbName, dataSources, selectMap) => {
  let select = ['iri','id','object_type'];
  let idArray = [];
  if (!Array.isArray(id)) {
    idArray = [id];
  } else {
    idArray = id;
  }

  let removedIds = []
  for (let itemId of idArray) {
    let response;
    if (!checkIfValidUUID(itemId)) throw new CyioError(`Invalid identifier: ${itemId}`);  

    // check if object with id exists
    let sparqlQuery = selectSystemImplementationQuery(itemId, select);
    try {
      response = await dataSources.Stardog.queryById({
        dbName: dbName,
        sparqlQuery,
        queryId: "Select System Implementation",
        singularizeSchema: singularizeSystemImplementationSchema
      });
    } catch (e) {
      console.log(e)
      throw e
    }
    
    if (response === undefined || response.length === 0) throw new CyioError(`Entity does not exist with ID ${itemId}`);

    // detach the information type from the catalog
    // await removeInformationTypeFromCatalog(catalogId, id, dbName, dataSources);

    // Delete any associated confidentiality impact
    // if (response[0].confidentiality_impact ) {
    //   let sparqlQuery = deleteImpactDefinitionByIriQuery(response[0].confidentiality_impact);
    //   try {
    //     let results = await dataSources.Stardog.delete({
    //       dbName: dbName,
    //       sparqlQuery,
    //       queryId: "Delete Confidentiality Impact"
    //     });
    //   } catch (e) {
    //     console.log(e)
    //     throw e
    //   }
    // }

    // Delete any associated integrity impact
    // if (response[0].integrity_impact ) {
    //   let sparqlQuery = deleteImpactDefinitionByIriQuery(response[0].integrity_impact);
    //   try {
    //     let results = await dataSources.Stardog.delete({
    //       dbName: dbName,
    //       sparqlQuery,
    //       queryId: "Delete Integrity Impact"
    //     });
    //   } catch (e) {
    //     console.log(e)
    //     throw e
    //   }
    // }
    
    // Delete any associated availability impact
    // if (response[0].availability_impact ) {
    //   let sparqlQuery = deleteImpactDefinitionByIriQuery(response[0].availability_impact);
    //   try {
    //     let results = await dataSources.Stardog.delete({
    //       dbName: dbName,
    //       sparqlQuery,
    //       queryId: "Delete Availability Impact"
    //     });
    //   } catch (e) {
    //     console.log(e)
    //     throw e
    //   }
    // }

    sparqlQuery = deleteSystemImplementationQuery(itemId);
    try {
      response = await dataSources.Stardog.delete({
        dbName: dbName,
        sparqlQuery,
        queryId: "Delete System Implementation"
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

export const editSystemImplementationById = async (id, input, dbName, dataSources, selectMap, schema) => {
  if (!checkIfValidUUID(id)) throw new CyioError(`Invalid identifier: ${id}`);  

  // make sure there is input data containing what is to be edited
  if (input === undefined || input.length === 0) throw new CyioError(`No input data was supplied`);

  // WORKAROUND to remove immutable fields
  input = input.filter(element => (element.key !== 'id' && element.key !== 'created' && element.key !== 'modified'));

  // check that the object to be edited exists with the predicates - only get the minimum of data
  let editSelect = ['id','created','modified'];
  for (let editItem of input) {
    editSelect.push(editItem.key);
  }

  const sparqlQuery = selectSystemImplementationQuery(id, editSelect );
  let response = await dataSources.Stardog.queryById({
    dbName: dbName,
    sparqlQuery,
    queryId: "Select System Implementation",
    singularizeSchema: singularizeSystemImplementationSchema
  });
  if (response.length === 0) throw new CyioError(`Entity does not exist with ID ${id}`);

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
        default:
          fieldType = 'simple';
          break;
      }

      if (fieldType === 'id') {
        // continue to next item if nothing to do
        if (editItem.operation === 'skip') continue;

        let sparqlQuery = selectObjectIriByIdQuery(value, objectType);
        let result = await dataSources.Stardog.queryById({
          dbName: dbName,
          sparqlQuery,
          queryId: "Obtaining IRI for the object with id",
          singularizeSchema: singularizeSystemImplementationSchema
        });
        if (result === undefined || result.length === 0) throw new CyioError(`Entity does not exist with ID ${value}`);
        iris.push(`<${result[0].iri}>`);
      }
    }
    if (iris.length > 0) editItem.value = iris;
  }    

  const query = updateQuery(
    `http://cyio.darklight.ai/system-implementation--${id}`,
    "http://csrc.nist.gov/ns/oscal/info-system#SystemImplementation",
    input,
    systemImplementationPredicateMap
  );
  if (query !== null) {
    let response;
    try {
      response = await dataSources.Stardog.edit({
        dbName: dbName,
        sparqlQuery: query,
        queryId: "Update System Implementation"
      });  
    } catch (e) {
      console.log(e)
      throw e
    }
  }

  const selectQuery = selectSystemImplementationQuery(id, selectMap.getNode("editSystemImplementation"));
  const result = await dataSources.Stardog.queryById({
    dbName: dbName,
    sparqlQuery: selectQuery,
    queryId: "Select System Implementation",
    singularizeSchema: singularizeSystemImplementationSchema
  });
  const reducer = getReducer("SYSTEM-IMPLEMENTATION");
  return reducer(result[0]);
};
  