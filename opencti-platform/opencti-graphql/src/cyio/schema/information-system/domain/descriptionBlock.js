import { UserInputError } from 'apollo-server-errors';
import { compareValues, filterValues, updateQuery, checkIfValidUUID, validateEnumValue } from '../../utils.js';
import { selectObjectIriByIdQuery } from '../../global/global-utils.js';
import {
  getReducer,
  descriptionBlockPredicateMap,
  singularizeDescriptionBlockSchema,
  selectDescriptionBlockQuery,
  selectDescriptionBlockByIriQuery,
  selectAllDescriptionBlocksQuery,
  insertDescriptionBlockQuery,
  deleteDescriptionBlockQuery,
  deleteDescriptionBlockByIriQuery,
  attachToDescriptionBlockQuery,
  detachFromDescriptionBlockQuery,
  // Diagram
  diagramPredicateMap,
  singularizeDiagramSchema,
  selectDiagramQuery,
  selectDiagramByIriQuery,
  selectAllDiagramsQuery,
  insertDiagramQuery,
  deleteDiagramQuery,
  deleteDiagramByIriQuery,
} from '../schema/sparql/descriptionBlock.js';


// Description Block
export const findDescriptionBlockById = async (id, dbName, dataSources, select) => {
  // ensure the id is a valid UUID
  if (!checkIfValidUUID(id)) throw new UserInputError(`Invalid identifier: ${id}`);

  let iri = `<http://cyio.darklight.ai/description-block--${id}>`;
  return findDescriptionBlockByIri(iri, dbName, dataSources, select);
}

export const findDescriptionBlockByIri = async (iri, dbName, dataSources, select) => {
  const sparqlQuery = selectDescriptionBlockByIriQuery(iri, select);
  let response;
  try {
    response = await dataSources.Stardog.queryById({
      dbName: dbName,
      sparqlQuery,
      queryId: "Select Description Block",
      singularizeSchema: singularizeDescriptionBlockSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }

  if (response === undefined || response === null || response.length === 0) return null;
  const reducer = getReducer("DESCRIPTION-BLOCK");
  return reducer(response[0]);  
};

export const findAllDescriptionBlocks = async (args, dbName, dataSources, select ) => {
  const sparqlQuery = selectAllDescriptionBlocksQuery(select, args);
  let response;
  try {
    response = await dataSources.Stardog.queryAll({
      dbName: dbName,
      sparqlQuery,
      queryId: "Select List of Description Blocks",
      singularizeSchema: singularizeDescriptionBlockSchema
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
  const reducer = getReducer("DESCRIPTION-BLOCK");
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

export const createDescriptionBlock = async (input, dbName, dataSources, select) => {
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
  if (input.description !== undefined ) {
    input.description = input.description.replace(/\s+/g, ' ')
                                        .replace(/\n/g, '\\n')
                                        .replace(/\"/g, '\\"')
                                        .replace(/\'/g, "\\'")
                                        .replace(/[\u2019\u2019]/g, "\\'")
                                        .replace(/[\u201C\u201D]/g, '\\"');
  }

  // Collect all the nested definitions and remove them from input array
  let nestedDefinitions = {
    'diagrams': { values: input.diagrams, props: {}, objectType: 'diagram', insertFunction: insertDiagramQuery}
  };
	for (let [fieldName, fieldInfo] of Object.entries(nestedDefinitions)) {
    if (fieldInfo.values === undefined || fieldInfo.values === null) continue;
    if (!Array.isArray(fieldInfo.values)) fieldInfo.values = [fieldInfo.values];
    for( let fieldValue of fieldInfo.values) {
      for (let [key, value] of Object.entries(fieldValue)) {
        if (typeof value === 'string') {
          value = value.replace(/\s+/g, ' ')
                        .replace(/\n/g, '\\n')
                        .replace(/\"/g, '\\"')
                        .replace(/\'/g, "\\'")
                        .replace(/[\u2019\u2019]/g, "\\'")
                        .replace(/[\u201C\u201D]/g, '\\"');
        }
        if (value === undefined || value === null) continue;
        nestedDefinitions[fieldName]['props'][key] = value;
      }
    }
    if (input.fieldName) delete input[fieldName];
  }

  // create the Description Block object
  let response;
  let {iri, id, query} = insertDescriptionBlockQuery(input);
  try {
    response = await dataSources.Stardog.create({
      dbName: dbName,
      sparqlQuery: query,
      queryId: "Create Description Block object"
      });
  } catch (e) {
    console.log(e)
    throw e
  }

  // Attach any impact definitions
  for (let [key, value] of Object.entries(nestedDefinitions)) {
		let itemName = value.objectType;
    if (Object.keys(value.props).length !== 0 ) {
      let {iri: itemIri, id: itemId, query} = value.insertFunction(value.props);
      try {
        // Create Impact Definition
        response = await dataSources.Stardog.create({
          dbName,
          sparqlQuery: query,
          queryId: `Create ${itemName}`
          });
      } catch (e) {
        console.log(e)
        throw e
      }

      // attach the definition to the new Description Block
      let attachQuery = attachToDescriptionBlockQuery(id, key, itemIri );
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

  // retrieve the newly created Description Block to be returned
  const selectQuery = selectDescriptionBlockQuery(id, select);
  let result;
  try {
    result = await dataSources.Stardog.queryById({
      dbName: dbName,
      sparqlQuery: selectQuery,
      queryId: "Select Description Block object",
      singularizeSchema: singularizeDescriptionBlockSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }
  if (result === undefined || result === null || result.length === 0) return null;
  const reducer = getReducer("DESCRIPTION-BLOCK");
  return reducer(result[0]);
};

export const deleteDescriptionBlockById = async ( id, dbName, dataSources) => {
  let select = ['iri','id','object_type','diagrams'];
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
    let sparqlQuery = selectDescriptionBlockQuery(itemId, select);
    try {
      response = await dataSources.Stardog.queryById({
        dbName: dbName,
        sparqlQuery,
        queryId: "Select Description Block",
        singularizeSchema: singularizeDescriptionBlockSchema
      });
    } catch (e) {
      console.log(e)
      throw e
    }
    
    if (response === undefined || response.length === 0) throw new UserInputError(`Entity does not exist with ID ${itemId}`);
    let descriptionBlock = response[0];

    // Delete any diagrams associated with the Description Block
    if (descriptionBlock.diagrams !== undefined) {
      for (let diagram of descriptionBlock.diagrams) {
        // WORK AROUND
        if (!diagram.includes('diagram')) continue;
        // END WORK AROUND
        let query = deleteDiagramByIriQuery(diagram);
        try {
          response = await dataSources.Stardog.delete({
            dbName: dbName,
            sparqlQuery: query,
            queryId: "Delete diagram"
          })
        } catch (e) {
          console.log(e)
          throw e
        }
      }
    }

    sparqlQuery = deleteDescriptionBlockQuery(itemId);
    try {
      response = await dataSources.Stardog.delete({
        dbName: dbName,
        sparqlQuery,
        queryId: "Delete Description Block"
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

export const deleteDescriptionBlockByIri = async ( iri, dbName, dataSources) => {
  let select = ['iri','id','object_type','diagrams'];
  let response;

  // check if object with id exists
  let sparqlQuery = selectDescriptionBlockByIriQuery(iri, select);
  try {
    response = await dataSources.Stardog.queryById({
      dbName: dbName,
      sparqlQuery,
      queryId: "Select Description Block",
      singularizeSchema: singularizeDescriptionBlockSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }
  
  if (response === undefined || response.length === 0) throw new UserInputError(`Entity does not exist with Iri ${iri}`);
  let descriptionBlock = response[0];

  // Delete any diagrams associated with the Description Block
  if (descriptionBlock.diagrams !== undefined) {
    for (let diagram of descriptionBlock.diagrams) {
      // WORK AROUND
      if (!diagram.includes('diagram')) continue;
      // END WORK AROUND
      let query = deleteDiagramByIriQuery(diagram);
      try {
        response = await dataSources.Stardog.delete({
          dbName: dbName,
          sparqlQuery: query,
          queryId: "Delete diagram"
        })
      } catch (e) {
        console.log(e)
        throw e
      }
    }
  }

  sparqlQuery = deleteDescriptionBlockByIriQuery(iri);
  try {
    response = await dataSources.Stardog.delete({
      dbName: dbName,
      sparqlQuery,
      queryId: "Delete Description Block"
    });
  } catch (e) {
    console.log(e)
    throw e
  }

  return iri;
};

export const editDescriptionBlockById = async (id, input, dbName, dataSources, selectMap, schema) => {
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

  const sparqlQuery = selectDescriptionBlockQuery(id, editSelect );
  let response = await dataSources.Stardog.queryById({
    dbName: dbName,
    sparqlQuery,
    queryId: "Select Description Block",
    singularizeSchema: singularizeDescriptionBlockSchema
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
        case 'diagrams':
          throw new UserInputError(`Cannot directly edit field "${editItem.key}".`);
        // case 'diagrams':
        //   if (editItem.operation !== 'add') {
        //     // find the existing update entity in Description Block
        //     if (editItem.key in response[0]) {
        //       entityIri = response[0].availability_impact;

        //       // detach the private FrequencyTiming object
        //       let query = detachFromDescriptionBlockQuery(id, editItem.key, entityIri);
        //       await dataSources.Stardog.delete({
        //         dbName: dbName,
        //         sparqlQuery: query,
        //         queryId: "Detach Impact from Description Block"
        //       });

        //       // Delete the Diagram object since its private to the Description Block
        //       query = deleteDiagramByIriQuery(entityIri);
        //       await dataSources.Stardog.delete({
        //         dbName: dbName,
        //         sparqlQuery: query,
        //         queryId: "Delete Diagram"
        //       });  
        //     }
        //   }
        //   if (editItem.operation !== 'delete') {
        //     let entity;
        //     objArray = JSON.parse(value);
        //     if (Array.isArray(objArray)) {
        //       entity = objArray[0];
        //     }
        //     else {
        //       entity = objArray;
        //     }

        //     // create the instance of the Diagram
        //     const { iri, id, query } = insertDiagramQuery(entity);
        //     await dataSources.Stardog.create({
        //       dbName: dbName,
        //       sparqlQuery: query,
        //       queryId: "Create Diagram Ref of Information Type Entry"
        //     });

        //     // attach the new Impact Definition to the Information Type Entry
        //     let attachQuery = attachToDescriptionBlockQuery(id, editItem.key, iri);
        //     await dataSources.Stardog.create({
        //       dbName: dbName,
        //       sparqlQuery: attachQuery,
        //       queryId: "Attach Diagram Ref object to Information Type Entry"
        //     });
        //   }
        //   fieldType = 'complex';
        //   editItem.operation  = 'skip';
        //   break;
        case 'links':
          objectType = 'external-reference';
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
          dbName: dbName,
          sparqlQuery,
          queryId: "Obtaining IRI for the object with id",
          singularizeSchema: singularizeDescriptionBlockSchema
        });
        if (result === undefined || result.length === 0) throw new UserInputError(`Entity does not exist with ID ${value}`);
        iris.push(`<${result[0].iri}>`);
      }
    }
    if (iris.length > 0) editItem.value = iris;
  }    

  const query = updateQuery(
    `http://cyio.darklight.ai/description-block--${id}`,
    'http://csrc.nist.gov/ns/oscal/info-system#DescriptionBlock',
    input,
    descriptionBlockPredicateMap
  );
  if (query !== null) {
    let response;
    try {
      response = await dataSources.Stardog.edit({
        dbName: dbName,
        sparqlQuery: query,
        queryId: "Update Description Block"
      });  
    } catch (e) {
      console.log(e)
      throw e
    }
  }

  const selectQuery = selectDescriptionBlockQuery(id, selectMap.getNode("editDescriptionBlock"));
  const result = await dataSources.Stardog.queryById({
    dbName: dbName,
    sparqlQuery: selectQuery,
    queryId: "Select Description Block",
    singularizeSchema: singularizeDescriptionBlockSchema
  });
  const reducer = getReducer("DESCRIPTION-BLOCK");
  return reducer(result[0]);
};

export const attachToDescriptionBlock = async (id, field, entityId, dbName, dataSources) => {
  let sparqlQuery;
  let select = ['id','iri','diagrams','links','remarks'];
  if (!checkIfValidUUID(id)) throw new UserInputError(`Invalid identifier: ${id}`);
  if (!checkIfValidUUID(entityId)) throw new UserInputError(`Invalid identifier: ${entityId}`);

  // check to see if the information system exists
  let iri = `<http://cyio.darklight.ai/description-block--${id}>`;
  sparqlQuery = selectDescriptionBlockByIriQuery(iri, select);
  let response;
  try {
    response = await dataSources.Stardog.queryById({
      dbName,
      sparqlQuery,
      queryId: "Select Description Block",
      singularizeSchema: singularizeDescriptionBlockSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }
  if (response === undefined || response === null || response.length === 0) throw new UserInputError(`Entity does not exist with ID ${id}`);

  let attachableObjects = {
    'diagrams': 'diagram',
    'links': 'link',
    'remarks': 'remark',
  }
  let objectType = attachableObjects[field];
  try {
    // check to see if the entity exists
    sparqlQuery = selectObjectIriByIdQuery(entityId, objectType);
    response = await dataSources.Stardog.queryById({
      dbName,
      sparqlQuery,
      queryId: "Obtaining IRI for the object with id",
      singularizeSchema: singularizeDescriptionBlockSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }
  if (response === undefined || response === null || response.length === 0) throw new UserInputError(`Entity does not exist with ID ${entityId}`);
  
  // check to make sure entity to be attached is proper for the field specified
  if (response[0].object_type !== attachableObjects[field]) throw new UserInputError(`Can not attach object of type '${response[0].object_type}' to field '${field}'`);

  // retrieve the IRI of the entity
  let entityIri = `<${response[0].iri}>`;

  // Attach the object to the information system
  sparqlQuery = attachToDescriptionBlockQuery(id, field, entityIri);
  try {
    response = await dataSources.Stardog.create({
      dbName,
      sparqlQuery,
      queryId: `Attach ${field} to Description Block`
      });
  } catch (e) {
    console.log(e)
    throw e
  }

  return true;
};

export const detachFromDescriptionBlock = async (id, field, entityId, dbName, dataSources) => {
  let sparqlQuery;
  if (!checkIfValidUUID(id)) throw new UserInputError(`Invalid identifier: ${id}`);
  if (!checkIfValidUUID(entityId)) throw new UserInputError(`Invalid identifier: ${entityId}`);

  // check to see if the information system exists
  let iri = `<http://cyio.darklight.ai/description-block--${id}>`;
  sparqlQuery = selectDescriptionBlockByIriQuery(iri, select);
  let response;
  try {
    response = await dataSources.Stardog.queryById({
      dbName,
      sparqlQuery,
      queryId: "Select Description Block",
      singularizeSchema: singularizeDescriptionBlockSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }
  if (response === undefined || response === null || response.length === 0) throw new UserInputError(`Entity does not exist with ID ${id}`);

  let attachableObjects = {
    'diagrams': 'diagram',
    'links': 'link',
    'remarks': 'remark',
  }
  let objectType = attachableObjects[field];
  try {
    // check to see if the entity exists
    sparqlQuery = selectObjectIriByIdQuery(entityId, objectType);
    response = await dataSources.Stardog.queryById({
      dbName,
      sparqlQuery,
      queryId: "Obtaining IRI for the object with id",
      singularizeSchema: singularizeDescriptionBlockSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }
  if (response === undefined || response === null || response.length === 0) throw new UserInputError(`Entity does not exist with ID ${entityId}`);

  // check to make sure entity to be attached is proper for the field specified
  if (response[0].object_type !== attachableObjects[field]) throw new UserInputError(`Can not attach object of type '${response[0].object_type}' to field '${field}'`);

  // retrieve the IRI of the entity
  let entityIri = `<${response[0].iri}>`;

  // Attach the object to the information system
  sparqlQuery = detachFromDescriptionBlockQuery(id, field, entityIri);
  try {
    response = await dataSources.Stardog.create({
      dbName,
      sparqlQuery,
      queryId: `Detach ${field} from Description Block`
      });
  } catch (e) {
    console.log(e)
    throw e
  }

  return true;
};



// Diagram Ref
export const findDiagramRefById = async (id, dbName, dataSources, select) => {
  // ensure the id is a valid UUID
  if (!checkIfValidUUID(id)) throw new UserInputError(`Invalid identifier: ${id}`);

  let iri = `<http://cyio.darklight.ai/diagram--${id}>`;
  return findDiagramRefByIri(iri, dbName, dataSources, select);
}

export const findDiagramRefByIri = async (iri, dbName, dataSources, select) => {
  const sparqlQuery = selectDiagramByIriQuery(iri, select);
  let response;
  try {
    response = await dataSources.Stardog.queryById({
      dbName: dbName,
      sparqlQuery,
      queryId: "Select Diagram",
      singularizeSchema: singularizeDiagramSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }

  if (response === undefined || response === null || response.length === 0) return null;
  const reducer = getReducer("DIAGRAM");
  return reducer(response[0]);  
};

export const findAllDiagramRefs = async (args, dbName, dataSources, select ) => {
  const sparqlQuery = selectAllDiagramsQuery(select, args);
  let response;
  try {
    response = await dataSources.Stardog.queryAll({
      dbName: dbName,
      sparqlQuery,
      queryId: "Select List of Diagrams",
      singularizeSchema: singularizeDiagramSchema
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
  const reducer = getReducer("DIAGRAM");
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

export const createDiagramRef = async (input, dbName, dataSources, select) => {
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
  if (input.description !== undefined ) {
    input.description = input.description.replace(/\s+/g, ' ')
                                        .replace(/\n/g, '\\n')
                                        .replace(/\"/g, '\\"')
                                        .replace(/\'/g, "\\'")
                                        .replace(/[\u2019\u2019]/g, "\\'")
                                        .replace(/[\u201C\u201D]/g, '\\"');
  }
  if (input.caption !== undefined) {
    input.caption = input.caption.replace(/\s+/g, ' ')
                                        .replace(/\n/g, '\\n')
                                        .replace(/\"/g, '\\"')
                                        .replace(/\'/g, "\\'")
                                        .replace(/[\u2019\u2019]/g, "\\'")
                                        .replace(/[\u201C\u201D]/g, '\\"');
  }

  // create the Diagram object
  let response;
  let {iri, id, query} = insertDiagramQuery(input);
  try {
    response = await dataSources.Stardog.create({
      dbName: dbName,
      sparqlQuery: query,
      queryId: "Create Diagram object"
      });
  } catch (e) {
    console.log(e)
    throw e
  }

  // retrieve the newly created Diagram to be returned
  const selectQuery = selectDiagramQuery(id, select);
  let result;
  try {
    result = await dataSources.Stardog.queryById({
      dbName: dbName,
      sparqlQuery: selectQuery,
      queryId: "Select Diagram object",
      singularizeSchema: singularizeDiagramSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }
  if (result === undefined || result === null || result.length === 0) return null;
  const reducer = getReducer("DIAGRAM");
  return reducer(result[0]);
};

export const deleteDiagramRefById = async ( id, dbName, dataSources ) => {
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
    if (!checkIfValidUUID(itemId)) throw new UserInputError(`Invalid identifier: ${itemId}`);  

    // check if object with id exists
    let sparqlQuery = selectDiagramQuery(itemId, select);
    try {
      response = await dataSources.Stardog.queryById({
        dbName: dbName,
        sparqlQuery,
        queryId: "Select Diagram",
        singularizeSchema: singularizeDiagramSchema
      });
    } catch (e) {
      console.log(e)
      throw e
    }
    if (response === undefined || response.length === 0) throw new UserInputError(`Entity does not exist with ID ${itemId}`);

    sparqlQuery = deleteDiagramQuery(itemId);
    try {
      response = await dataSources.Stardog.delete({
        dbName: dbName,
        sparqlQuery,
        queryId: "Delete Diagram"
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

export const deleteDiagramRefByIri = async ( iri, dbName, dataSources ) => {
  let select = ['iri','id','object_type'];
  let response;

  // check if object with id exists
  let sparqlQuery = selectDiagramByIriQuery(iri, select);
  try {
    response = await dataSources.Stardog.queryById({
      dbName: dbName,
      sparqlQuery,
      queryId: "Select Diagram",
      singularizeSchema: singularizeDiagramSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }
  
  if (response === undefined || response.length === 0) throw new UserInputError(`Entity does not exist with ID ${itemId}`);
  sparqlQuery = deleteDiagramByIriQuery(iri);
  try {
    response = await dataSources.Stardog.delete({
      dbName: dbName,
      sparqlQuery,
      queryId: "Delete Diagram"
    });
  } catch (e) {
    console.log(e)
    throw e
  }
    
  return iri;
};

export const editDiagramRefById = async (id, input, dbName, dataSources, select, schema) => {
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

  const sparqlQuery = selectDiagramQuery(id, editSelect );
  let response = await dataSources.Stardog.queryById({
    dbName: dbName,
    sparqlQuery,
    queryId: "Select Diagram",
    singularizeSchema: singularizeDiagramSchema
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
        case 'links':
          objectType = 'external-reference';
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
          dbName: dbName,
          sparqlQuery,
          queryId: "Obtaining IRI for the object with id",
          singularizeSchema: singularizeDiagramSchema
        });
        if (result === undefined || result.length === 0) throw new UserInputError(`Entity does not exist with ID ${value}`);
        iris.push(`<${result[0].iri}>`);
      }
    }
    if (iris.length > 0) editItem.value = iris;
  }    

  const query = updateQuery(
    `http://cyio.darklight.ai/diagram--${id}`,
    "http://csrc.nist.gov/ns/oscal/info-system#Diagram",
    input,
    diagramPredicateMap
  );
  if (query !== null) {
    let response;
    try {
      response = await dataSources.Stardog.edit({
        dbName: dbName,
        sparqlQuery: query,
        queryId: "Update Diagram"
      });  
    } catch (e) {
      console.log(e)
      throw e
    }
  }
  const selectQuery = selectDiagramQuery(id, select);
  const result = await dataSources.Stardog.queryById({
    dbName: dbName,
    sparqlQuery: selectQuery,
    queryId: "Select Diagram",
    singularizeSchema: singularizeDiagramSchema
  });
  const reducer = getReducer("DIAGRAM");
  return reducer(result[0]);
};
