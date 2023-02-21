import { UserInputError } from 'apollo-server-express';
import { compareValues, filterValues, updateQuery, checkIfValidUUID, validateEnumValue, CyioError } from '../../utils.js';
import conf from '../../../../config/conf';
import { selectObjectIriByIdQuery, findParentId, findParentIriQuery } from '../../global/global-utils.js';
import {
  getReducer,
  informationTypeEntryPredicateMap,
  singularizeInformationTypeEntrySchema,
  insertInformationTypeEntryQuery,
  selectInformationTypeEntryQuery,
  selectInformationTypeEntryByIriQuery,
  selectAllInformationTypeEntriesQuery,
  deleteInformationTypeEntryQuery,
  attachToInformationTypeEntryQuery,
  detachFromInformationTypeEntryQuery,
  impactDefinitionPredicateMap,
  singularizeImpactDefinitionSchema,
  selectImpactDefinitionQuery,
  selectImpactDefinitionByIriQuery,
  insertImpactDefinitionQuery,
  deleteImpactDefinitionQuery,
  deleteImpactDefinitionByIriQuery,
} from '../schema/sparql/informationTypeEntry.js';
import { addInformationTypeToCatalog } from '../domain/informationTypeCatalog.js';
import { attachToInformationTypeCatalogQuery, detachFromInformationTypeCatalogQuery } from '../schema/sparql/informationTypeCatalog.js';


// Information Type Entry
export const findInformationTypeEntryById = async (id, dbName, dataSources, select) => {
  // ensure the id is a valid UUID
  if (!checkIfValidUUID(id)) throw new CyioError(`Invalid identifier: ${id}`);

  let iri = `<http://cyio.darklight.ai/information-type-entry--${id}>`;
  return findInformationTypeEntryByIri(iri, dbName, dataSources, select);
}

export const findInformationTypeEntryByIri = async (iri, dbName, dataSources, select) => {
  let contextDB = conf.get('app:database:context') || 'cyber-context';
  const sparqlQuery = selectInformationTypeEntryByIriQuery(iri, select);
  let response;
  try {
    response = await dataSources.Stardog.queryById({
      dbName: contextDB,
      sparqlQuery,
      queryId: "Select Information Type Entry",
      singularizeSchema: singularizeInformationTypeEntrySchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }

  if (response === undefined || response === null || response.length === 0) return null;
  const reducer = getReducer("INFORMATION-TYPE-ENTRY");
  return reducer(response[0]);  
};

export const findAllInformationTypeEntries = async (args, dbName, dataSources, select ) => {
  let contextDB = conf.get('app:database:context') || 'cyber-context';
  const sparqlQuery = selectAllInformationTypeEntriesQuery(select, args);
  let response;
  try {
    response = await dataSources.Stardog.queryAll({
      dbName: contextDB,
      sparqlQuery,
      queryId: "Select List of Information Type Entries",
      singularizeSchema: singularizeInformationTypeEntrySchema
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
  const reducer = getReducer("INFORMATION-TYPE-ENTRY");
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

export const createInformationTypeEntry = async (input, dbName, dataSources, select) => {
  let contextDB = conf.get('app:database:context') || 'cyber-context';
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

  // Need to escape contents, remove explicit newlines, and collapse multiple what spaces.
  input.description = input.description.replace(/\s+/g, ' ')
                                       .replace(/\n/g, '\\n')
                                       .replace(/\"/g, '\\"')
                                       .replace(/\'/g, "\\'")
                                       .replace(/[\u2019\u2019]/g, "\\'")
                                       .replace(/[\u201C\u201D]/g, '\\"');

  let impactDefinitions = {
    'confidentiality': { props: {}, field: 'confidentiality_impact' },
    'integrity': { props: {}, field: 'integrity_impact' },
    'availability':{ props: {}, field: 'availability_impact' }
  };
  if (input.confidentiality_impact !== undefined) {
    for (let [key, value] of Object.entries(input.confidentiality_impact)) {
      impactDefinitions.confidentiality.props[key] = value.replace(/\s+/g, ' ')
                                                          .replace(/\n/g, '\\n')
                                                          .replace(/\"/g, '\\"')
                                                          .replace(/\'/g, "\\'")
                                                          .replace(/[\u2019\u2019]/g, "\\'")
                                                          .replace(/[\u201C\u201D]/g, '\\"');
    }
    delete input.confidentiality_impact;
  }

  if (input.integrity_impact !== undefined) {
    for (let [key, value] of Object.entries(input.integrity_impact)) {
      impactDefinitions.integrity.props[key] = value.replace(/\s+/g, ' ')
                                                    .replace(/\n/g, '\\n')
                                                    .replace(/\"/g, '\\"')
                                                    .replace(/\'/g, "\\'")
                                                    .replace(/[\u2019\u2019]/g, "\\'")
                                                    .replace(/[\u201C\u201D]/g, '\\"');
    }
    delete input.integrity_impact;
  }

  if (input.availability_impact !== undefined) {
    for (let [key, value] of Object.entries(input.availability_impact)) {
      impactDefinitions.availability.props[key] = value.replace(/\s+/g, ' ')
                                                       .replace(/\n/g, '\\n')
                                                       .replace(/\"/g, '\\"')
                                                       .replace(/\'/g, "\\'")
                                                       .replace(/[\u2019\u2019]/g, "\\'")
                                                       .replace(/[\u201C\u201D]/g, '\\"');
    }
    delete input.availability_impact;
  }

  // create the Information Type Entry object
  let response;
  let {iri, id, query} = insertInformationTypeEntryQuery(input);
  try {
    response = await dataSources.Stardog.create({
      dbName: contextDB,
      sparqlQuery: query,
      queryId: "Create Information Type Entry object"
      });
  } catch (e) {
    console.log(e)
    throw e
  }

  // Attach any impact definitions
  for (let [key, value] of Object.entries(impactDefinitions)) {
    // Create the Impact Definition
    if (Object.keys(value.props).length !== 0 ) {
      let {iri:impactIri, id:impactId, query} = insertImpactDefinitionQuery(value.props);
      try {
        // Create Impact Definition
        response = await dataSources.Stardog.create({
          dbName: contextDB,
          sparqlQuery: query,
          queryId: "Create Impact Definition"
          });
      } catch (e) {
        console.log(e)
        throw e
      }

      // attach the Impact Definition to the new Information Type entry
      let attachQuery = attachToInformationTypeEntryQuery(id, value.field, impactIri );
      try {
        response = await dataSources.Stardog.create({
          dbName: contextDB,
          sparqlQuery: attachQuery,
          queryId: "Attach Impact Definition"
          });
      } catch (e) {
        console.log(e)
        throw e
      }
    }
  }

  // attach the new information type to the catalog
  await addInformationTypeToCatalog(input.catalog_id, id, dbName, dataSources);

  // retrieve the newly created Information Type Entry to be returned
  const selectQuery = selectInformationTypeEntryQuery(id, select);
  let result;
  try {
    result = await dataSources.Stardog.queryById({
      dbName: contextDB,
      sparqlQuery: selectQuery,
      queryId: "Select Information Type Entry object",
      singularizeSchema: singularizeInformationTypeEntrySchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }
  if (result === undefined || result === null || result.length === 0) return null;
  const reducer = getReducer("INFORMATION-TYPE-ENTRY");
  return reducer(result[0]);
};

export const deleteInformationTypeEntryById = async ( id, catalogId, dbName, dataSources ) => {
  let contextDB = conf.get('app:database:context') || 'cyber-context';
  let select = ['iri','id','object_type','system','title','confidentiality_impact','integrity_impact','availability_impact','catalog'];
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
    let sparqlQuery = selectInformationTypeEntryQuery(itemId, select);
    try {
      response = await dataSources.Stardog.queryById({
        dbName: contextDB,
        sparqlQuery,
        queryId: "Select Information Type Entry",
        singularizeSchema: singularizeInformationTypeEntrySchema
      });
    } catch (e) {
      console.log(e)
      throw e
    }
    
    if (response === undefined || response.length === 0) throw new CyioError(`Entity does not exist with ID ${itemId}`);

    // detach the information type from the catalog
    await removeInformationTypeFromCatalog(catalogId, id, dbName, dataSources);

    // Delete any associated confidentiality impact
    if (response[0].confidentiality_impact ) {
      let sparqlQuery = deleteImpactDefinitionByIriQuery(response[0].confidentiality_impact);
      try {
        let results = await dataSources.Stardog.delete({
          dbName: contextDB,
          sparqlQuery,
          queryId: "Delete Confidentiality Impact"
        });
      } catch (e) {
        console.log(e)
        throw e
      }
    }

    // Delete any associated integrity impact
    if (response[0].integrity_impact ) {
      let sparqlQuery = deleteImpactDefinitionByIriQuery(response[0].integrity_impact);
      try {
        let results = await dataSources.Stardog.delete({
          dbName: contextDB,
          sparqlQuery,
          queryId: "Delete Integrity Impact"
        });
      } catch (e) {
        console.log(e)
        throw e
      }
    }
    
    // Delete any associated availability impact
    if (response[0].availability_impact ) {
      let sparqlQuery = deleteImpactDefinitionByIriQuery(response[0].availability_impact);
      try {
        let results = await dataSources.Stardog.delete({
          dbName: contextDB,
          sparqlQuery,
          queryId: "Delete Availability Impact"
        });
      } catch (e) {
        console.log(e)
        throw e
      }
    }

    sparqlQuery = deleteInformationTypeEntryQuery(itemId);
    try {
      response = await dataSources.Stardog.delete({
        dbName: contextDB,
        sparqlQuery,
        queryId: "Delete Information Type Entry"
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

export const editInformationTypeEntryById = async (id, input, dbName, dataSources, select, schema) => {
  let contextDB = conf.get('app:database:context') || 'cyber-context';
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

  const sparqlQuery = selectInformationTypeEntryQuery(id, editSelect );
  let response = await dataSources.Stardog.queryById({
    dbName: contextDB,
    sparqlQuery,
    queryId: "Select Information Type Entry",
    singularizeSchema: singularizeInformationTypeEntrySchema
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
        case 'base_score':
          if (!validateEnumValue(value, 'FIPS199', schema)) throw new CyioError(`Invalid value "${value}" for field "${editItem.key}".`);
          editItem.value[0] = value.replace(/_/g,'-').toLowerCase();
          fieldType = 'simple';
          break;
        case 'confidentiality_impact':
        case 'integrity_impact':
        case 'availability_impact':
          if (editItem.operation !== 'add') {
            // find the existing update entity in Information Type Entry
            if (editItem.key in response[0]) {
              let entityIri;
              if (editItem.key === 'confidentiality_impact') entityIri = response[0].confidentiality_impact;
              if (editItem.key === 'integrity_impact') entityIri = response[0].integrity_impact;
              if (editItem.key === 'availability_impact') entityIri = response[0].availability_impact;

              // detach the private FrequencyTiming object
              let query = detachFromInformationTypeEntryQuery(id, editItem.key, entityIri);
              await dataSources.Stardog.delete({
                dbName: contextDB,
                sparqlQuery: query,
                queryId: "Detach Impact from Information Type Entry"
              });

              // Delete the Impact Definition object since its private to the Information Type Entry
              query = deleteImpactDefinitionByIriQuery(entityIri);
              await dataSources.Stardog.delete({
                dbName: contextDB,
                sparqlQuery: query,
                queryId: "Delete Impact Definition"
              });  
            }
          }
          if (editItem.operation !== 'delete') {
            let entity;
            objArray = JSON.parse(value);
            if (Array.isArray(objArray)) {
              entity = objArray[0];
            }
            else {
              entity = objArray;
            }

            // create the instance of the Impact Definition
            const { iri, id, query } = insertImpactDefinitionQuery(entity);
            await dataSources.Stardog.create({
              dbName: contextDB,
              sparqlQuery: query,
              queryId: "Create Impact Definition of Information Type Entry"
            });

            // attach the new Impact Definition to the Information Type Entry
            let attachQuery = attachToInformationTypeEntryQuery(id, editItem.key, iri);
            await dataSources.Stardog.create({
              dbName: contextDB,
              sparqlQuery: attachQuery,
              queryId: "Attach Impact Definition object to Information Type Entry"
            });
          }
          fieldType = 'complex';
          editItem.operation  = 'skip';
          break;
        default:
          fieldType = 'simple';
          break;
      }

      if (fieldType === 'id') {
        // continue to next item if nothing to do
        if (editItem.operation === 'skip') continue;

        // let iri = `${objectMap[objectType].iriTemplate}-${value}`;
        let sparqlQuery = selectObjectIriByIdQuery(value, objectType);
        let result = await dataSources.Stardog.queryById({
          dbName: contextDB,
          sparqlQuery,
          queryId: "Obtaining IRI for the object with id",
          singularizeSchema: singularizeInformationTypeEntrySchema
        });
        if (result === undefined || result.length === 0) throw new CyioError(`Entity does not exist with ID ${value}`);
        iris.push(`<${result[0].iri}>`);
      }
    }
    if (iris.length > 0) editItem.value = iris;
  }    

  const query = updateQuery(
    `http://cyio.darklight.ai/information-type-entry--${id}`,
    "http://nist.gov/ns/sp800-60#InformationTypeEntry",
    input,
    informationTypeEntryPredicateMap
  );
  if (query !== null) {
    let response;
    try {
      response = await dataSources.Stardog.edit({
        dbName: contextDB,
        sparqlQuery: query,
        queryId: "Update Information Type Entry"
      });  
    } catch (e) {
      console.log(e)
      throw e
    }
  }

  const selectQuery = selectInformationTypeEntryQuery(id, select);
  const result = await dataSources.Stardog.queryById({
    dbName: contextDB,
    sparqlQuery: selectQuery,
    queryId: "Select Information Type Entry",
    singularizeSchema: singularizeInformationTypeEntrySchema
  });
  const reducer = getReducer("INFORMATION-TYPE-ENTRY");
  return reducer(result[0]);
};

// Impact Definition
export const findImpactDefinitionById = async (id, dbName, dataSources, select) => {
  if (!checkIfValidUUID(id)) throw new CyioError(`Invalid identifier: ${id}`);

  let iri = `<http://cyio.darklight.ai/impact-definition--${id}>`;
  return findImpactDefinitionByIri(iri, dbName, dataSources, select) ;
};

export const findImpactDefinitionByIri = async (iri, dbName, dataSources, select) => {
  let contextDB = conf.get('app:database:context') || 'cyber-context';
  const sparqlQuery = selectImpactDefinitionByIriQuery(iri, select);
  let response;
  try {
    response = await dataSources.Stardog.queryById({
      dbName: contextDB,
      sparqlQuery,
      queryId: "Select Impact Definition",
      singularizeSchema: singularizeImpactDefinitionSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }

  if (response === undefined) return null;
  if (Array.isArray(response) && response.length > 0) {
    const reducer = getReducer("IMPACT-DEFINITION");
    return reducer(response[0]);  
  }
};

export const createImpactDefinition = async (input, dbName, dataSources, select) => {
  let contextDB = conf.get('app:database:context') || 'cyber-context';
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

  // create the Impact Definition
  let response;
  let {iri, id, query} = insertImpactDefinitionQuery(input);
  try {
    response = await dataSources.Stardog.create({
      dbName: contextDB,
      sparqlQuery: query,
      queryId: "Create Impact Definition"
      });
  } catch (e) {
    console.log(e)
    throw e
  }

  // retrieve the newly created Impact Definition to be returned
  const selectQuery = selectImpactDefinitionQuery(id, select);
  const result = await dataSources.Stardog.queryById({
    dbName: contextDB,
    sparqlQuery: selectQuery,
    queryId: "Select Connection Information object",
    singularizeSchema: singularizeImpactDefinitionSchema
  });
  const reducer = getReducer("INFORMATION-TYPE-ENTRY");
  return reducer(result[0]);
};

export const deleteImpactDefinitionById = async ( id, dbName, dataSources) => {
  let contextDB = conf.get('app:database:context') || 'cyber-context';
  let select = ['id','object_type'];
  if (!Array.isArray(id)) {
    if (!checkIfValidUUID(id)) throw new CyioError(`Invalid identifier: ${id}`);

    // check if object with id exists
    let sparqlQuery = selectImpactDefinitionQuery(id, select);
    let response;
    try {
      response = await dataSources.Stardog.queryById({
        dbName: contextDB,
        sparqlQuery,
        queryId: "Select Impact Definition",
        singularizeSchema: singularizeInformationTypeEntrySchema
      });
    } catch (e) {
      console.log(e)
      throw e
    }
    if (response === undefined || response.length === 0) throw new CyioError(`Entity does not exist with ID ${id}`);

    // delete the object
    sparqlQuery = deleteInformationTypeEntryQuery(id);
    try {
      response = await dataSources.Stardog.delete({
        dbName: contextDB,
        sparqlQuery,
        queryId: "Delete Information Type Entry"
      });
    } catch (e) {
      console.log(e)
      throw e
    }
    
    return connectionId;
  } 

  if (Array.isArray(id)) {
    let removedIds = []
    for (let itemId of id) {
      let response;
      if (!checkIfValidUUID(itemId)) throw new CyioError(`Invalid identifier: ${itemId}`);  

      // check if object with id exists
      let sparqlQuery = selectInformationTypeEntryQuery(itemId, select);
      try {
        response = await dataSources.Stardog.queryById({
          dbName: contextDB,
          sparqlQuery,
          queryId: "Select Information Type Entry",
          singularizeSchema: singularizeInformationTypeEntrySchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }
      
      if (response === undefined || response.length === 0) throw new CyioError(`Entity does not exist with ID ${itemId}`);

      sparqlQuery = deleteInformationTypeEntryQuery(itemId);
      try {
        response = await dataSources.Stardog.delete({
          dbName: contextDB,
          sparqlQuery,
          queryId: "Delete Information Type Entry"
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


