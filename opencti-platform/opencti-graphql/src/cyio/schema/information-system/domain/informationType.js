import { UserInputError } from 'apollo-server-errors';
import { compareValues, filterValues, updateQuery, checkIfValidUUID, validateEnumValue } from '../../utils.js';
import conf from '../../../../config/conf';
import { selectObjectIriByIdQuery } from '../../global/global-utils.js';
import {
  getReducer,
	// Information Type
  informationTypePredicateMap,
  singularizeInformationTypeSchema,
  selectInformationTypeQuery,
  selectInformationTypeByIriQuery,
  selectAllInformationTypesQuery,
  insertInformationTypeQuery,
  deleteInformationTypeQuery,
  attachToInformationTypeQuery,
  detachFromInformationTypeQuery,
	// Impact Definition
  impactDefinitionPredicateMap,
  singularizeImpactDefinitionSchema,
  selectImpactDefinitionQuery,
  selectImpactDefinitionByIriQuery,
  selectAllImpactDefinitionsQuery,
  insertImpactDefinitionQuery,
  deleteImpactDefinitionQuery,
  deleteImpactDefinitionByIriQuery,
  attachToImpactDefinitionQuery,
  detachFromImpactDefinitionQuery,
} from '../schema/sparql/informationType.js';


// Information Type
export const findInformationTypeById = async (id, dbName, dataSources, select) => {
  // ensure the id is a valid UUID
  if (!checkIfValidUUID(id)) throw new UserInputError(`Invalid identifier: ${id}`);

  let iri = `<http://cyio.darklight.ai/information-type--${id}>`;
  return findInformationTypeByIri(iri, dbName, dataSources, select);
}

export const findInformationTypeByIri = async (iri, dbName, dataSources, select) => {
  if (select.includes('display_name')) {
    if (!select.includes('title')) select.push('title');
    if (!select.includes('identifier')) select.push('identifier');
  }
  
  const sparqlQuery = selectInformationTypeByIriQuery(iri, select);
  let response;
  try {
    response = await dataSources.Stardog.queryById({
      dbName,
      sparqlQuery,
      queryId: "Select Information Type",
      singularizeSchema: singularizeInformationTypeSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }
  if (response === undefined || response === null || response.length === 0) return null;

  if (select.includes('display_name')) {
    let display_name = (response[0].identifier ? response[0].identifier : '') + "  " +
                        (response[0].title ? response[0].title : '');
    display_name = display_name.trim();
    if (display_name.length > 0) response[0].display_name = display_name;
  }

  const reducer = getReducer("INFORMATION-TYPE");
  return reducer(response[0]);  
};

export const findAllInformationTypes = async (args, dbName, dataSources, select ) => {
  if (select.includes('display_name')) {
    if (!select.includes('title')) select.push('title');
    if (!select.includes('identifier')) select.push('identifier');
  }

  const sparqlQuery = selectAllInformationTypesQuery(select, args);
  let response;
  try {
    response = await dataSources.Stardog.queryAll({
      dbName,
      sparqlQuery,
      queryId: "Select List of Information Types",
      singularizeSchema: singularizeInformationTypeSchema
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
  const reducer = getReducer("INFORMATION-TYPE");
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

    if (select.includes('display_name')) {
      let display_name = (resultItem.identifier ? resultItem.identifier : '') + "  " +
                          (resultItem.title ? result.title : '');
      display_name = display_name.trim();
      if (display_name.length > 0) response[0].display_name = display_name;
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

export const createInformationType = async (input, dbName, dataSources, select) => {
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
    input.title = input.title.replace(/\s+/g, ' ')
                                        .replace(/\n/g, '\\n')
                                        .replace(/\"/g, '\\"')
                                        .replace(/\'/g, "\\'")
                                        .replace(/[\u2019\u2019]/g, "\\'")
                                        .replace(/[\u201C\u201D]/g, '\\"');
  }
  if (input.description !== undefined) {
    input.description = input.description.replace(/\s+/g, ' ')
																				.replace(/\n/g, '\\n')
																				.replace(/\"/g, '\\"')
																				.replace(/\'/g, "\\'")
																				.replace(/[\u2019\u2019]/g, "\\'")
																				.replace(/[\u201C\u201D]/g, '\\"');
  }

  // Collect all the nested definitions and remove them from input array
  let nestedDefinitions = {
		'confidentiality_impact': { values: input.confidentiality_impact, props: {}, objectType: 'impact-definition', insertFunction: insertImpactDefinitionQuery },
		'integrity_impact': { values: input.integrity_impact, props: {}, objectType: 'impact-definition', insertFunction: insertImpactDefinitionQuery} ,
		'availability_impact': { values: input.availability_impact, props: {}, objectType: 'impact-definition', insertFunction: insertImpactDefinitionQuery },
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
        nestedDefinitions[fieldName]['props'][key] = value;
      }
    }
    if (input[fieldName]) delete input[fieldName];
  }

  // Collect all the referenced objects and remove them from input array
  let objectReferences = {
    'categorizations': { ids: input.categorizations, objectType: 'information-type-entry' },
  };
  if (input.categorizations) delete input.categorizations;
  
  // create the Information Type object
  let response;
  let {iri, id, query} = insertInformationTypeQuery(input);
  try {
    response = await dataSources.Stardog.create({
      dbName,
      sparqlQuery: query,
      queryId: "Create Information Type object"
      });
  } catch (e) {
    console.log(e)
    throw e
  }

  // Attach any impact definitions
  for (let [key, value] of Object.entries(nestedDefinitions)) {
		let itemName = value.objectType.replace(/-/g, ' ');
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

      // attach the definition to the new Information Type
      let attachQuery = attachToInformationTypeQuery(id, key, itemIri );
      try {
        response = await dataSources.Stardog.create({
          dbName,
          sparqlQuery: attachQuery,
          queryId: `Attach ${itemName}`
          });
      } catch (e) {
        console.log(e)
        throw e
      }
    }
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
        singularizeSchema: singularizeInformationTypeSchema
      });
      if (result === undefined || result.length === 0) throw new UserInputError(`Entity does not exist with ID ${refId}`);
      iris.push(`<${result[0].iri}>`);
    }

    if (iris.length > 0) {
      // attach the definition to the new Information Type
      let attachQuery = attachToInformationTypeQuery(id, key, iris );
      try {
        response = await dataSources.Stardog.create({
          dbName,
          sparqlQuery: attachQuery,
          queryId: `Attaching one or more ${itemName} to information system`
          });
      } catch (e) {
        console.log(e)
        throw e
      }
    }
  }

  // retrieve the newly created Information Type to be returned
  const selectQuery = selectInformationTypeQuery(id, select);
  let result;
  try {
    result = await dataSources.Stardog.queryById({
      dbName,
      sparqlQuery: selectQuery,
      queryId: "Select Information Type object",
      singularizeSchema: singularizeInformationTypeSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }
  if (result === undefined || result === null || result.length === 0) return null;
  const reducer = getReducer("INFORMATION-TYPE");
  return reducer(result[0]);
};

export const deleteInformationTypeById = async ( id, dbName, dataSources ) => {
  let select = ['iri','id','object_type','confidentiality_impact','integrity_impact','availability_impact'];
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
    let sparqlQuery = selectInformationTypeQuery(itemId, select);
    try {
      response = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery,
        queryId: "Select Information Type",
        singularizeSchema: singularizeInformationTypeSchema
      });
    } catch (e) {
      console.log(e)
      throw e
    }
    if (response === undefined || response.length === 0) throw new UserInputError(`Entity does not exist with ID ${itemId}`);

    // Delete any associated confidentiality impact
    if (response[0].confidentiality_impact ) {
      let sparqlQuery = deleteImpactDefinitionByIriQuery(response[0].confidentiality_impact);
      try {
        let results = await dataSources.Stardog.delete({
          dbName,
          sparqlQuery,
          queryId: "Delete Confidentiality Impact Definition"
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
          dbName,
          sparqlQuery,
          queryId: "Delete Integrity Impact Definition"
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
          dbName,
          sparqlQuery,
          queryId: "Delete Availability Impact Definition"
        });
      } catch (e) {
        console.log(e)
        throw e
      }
    }

    sparqlQuery = deleteInformationTypeQuery(itemId);
    try {
      response = await dataSources.Stardog.delete({
        dbName,
        sparqlQuery,
        queryId: "Delete Information Type"
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

export const editInformationTypeById = async ( id, input, dbName, dataSources, select, schema ) => {
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

  const sparqlQuery = selectInformationTypeQuery(id, editSelect );
  let response = await dataSources.Stardog.queryById({
    dbName,
    sparqlQuery,
    queryId: "Select Information Type",
    singularizeSchema: singularizeInformationTypeSchema
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
				case 'categorization':
          objectType = 'information-type-entry';
          fieldType = 'id';
          break;
        case 'responsible_parties':
          objectType = 'oscal-responsible-party';
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
        case 'confidentiality_impact':
        case 'integrity_impact':
        case 'availability_impact':
          if (editItem.operation !== 'add') {
            // find the existing update entity in Information Type
            if (editItem.key in response[0]) {
              let entityIri;
              if (editItem.key === 'confidentiality_impact') entityIri = response[0].confidentiality_impact;
              if (editItem.key === 'integrity_impact') entityIri = response[0].integrity_impact;
              if (editItem.key === 'availability_impact') entityIri = response[0].availability_impact;

              // detach the private Impact Definition object
              let query = detachFromInformationTypeQuery(id, editItem.key, entityIri);
              await dataSources.Stardog.delete({
                dbName,
                sparqlQuery: query,
                queryId: "Detach Impact from Information Type"
              });

              // Delete the Impact Definition object since its private to the Information Type
              query = deleteImpactDefinitionByIriQuery(entityIri);
              await dataSources.Stardog.delete({
                dbName,
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
            const { iri: impactDefinitionIri, id: impactDefinitionId, query } = insertImpactDefinitionQuery(entity);
            await dataSources.Stardog.create({
              dbName,
              sparqlQuery: query,
              queryId: "Create Impact Definition of Information Type "
            });

            // attach the new Impact Definition to the Information Type object
            let attachQuery = attachToInformationTypeQuery(id, editItem.key, impactDefinitionIri);
            await dataSources.Stardog.create({
              dbName,
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
          dbName,
          sparqlQuery,
          queryId: "Obtaining IRI for the object with id",
          singularizeSchema: singularizeInformationTypeSchema
        });
        if (result === undefined || result.length === 0) throw new UserInputError(`Entity does not exist with ID ${value}`);
        iris.push(`<${result[0].iri}>`);
      }
    }
    if (iris.length > 0) editItem.value = iris;
  }    

  const query = updateQuery(
    `http://cyio.darklight.ai/information-type--${id}`,
    "http://csrc.nist.gov/ns/oscal/info-system#InformationType",
    input,
    informationTypePredicateMap
  );
  if (query !== null) {
    let response;
    try {
      response = await dataSources.Stardog.edit({
        dbName,
        sparqlQuery: query,
        queryId: "Update Information Type"
      });  
    } catch (e) {
      console.log(e)
      throw e
    }
  }

  const selectQuery = selectInformationTypeQuery(id, select);
  const result = await dataSources.Stardog.queryById({
    dbName,
    sparqlQuery: selectQuery,
    queryId: "Select Information Type",
    singularizeSchema: singularizeInformationTypeSchema
  });
  const reducer = getReducer("INFORMATION-TYPE");
  return reducer(result[0]);
};

export const attachToInformationType = async ( id, field, entityId, dbName, dataSources ) => {
  let sparqlQuery;
  if (!checkIfValidUUID(id)) throw new UserInputError(`Invalid identifier: ${id}`);
  if (!checkIfValidUUID(entityId)) throw new UserInputError(`Invalid identifier: ${entityId}`);

  // check to see if the information system exists
  let iri = `<http://cyio.darklight.ai/information-type--${id}>`;
  sparqlQuery = selectInformationTypeByIriQuery(iri, select);
  let response;
  try {
    response = await dataSources.Stardog.queryById({
      dbName,
      sparqlQuery,
      queryId: "Select Information Type",
      singularizeSchema: singularizeInformationTypeSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }
  if (response === undefined || response === null || response.length === 0) throw new UserInputError(`Entity does not exist with ID ${id}`);

  let attachableObjects = {
		'categorizations': 'information-type-entry',
		'confidentiality_impact': 'impact-definition',
		'integrity_impact': 'impact-definition',
		'availability_impact': 'impact-definition',
    'information_types': 'information-type',
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
      singularizeSchema: singularizeInformationTypeSchema
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
  sparqlQuery = attachToInformationTypeQuery(id, field, entityIri);
  try {
    response = await dataSources.Stardog.create({
      dbName,
      sparqlQuery,
      queryId: `Attach ${field} to Information Type`
      });
  } catch (e) {
    console.log(e)
    throw e
  }

  return true;
};

export const detachFromInformationType = async ( id, field, entityId, dbName, dataSources ) => {
  let sparqlQuery;
  if (!checkIfValidUUID(id)) throw new UserInputError(`Invalid identifier: ${id}`);
  if (!checkIfValidUUID(entityId)) throw new UserInputError(`Invalid identifier: ${entityId}`);

  // check to see if the information system exists
  let iri = `<http://cyio.darklight.ai/information-type--${id}>`;
  sparqlQuery = selectInformationTypeByIriQuery(iri, select);
  let response;
  try {
    response = await dataSources.Stardog.queryById({
      dbName,
      sparqlQuery,
      queryId: "Select Information Type",
      singularizeSchema: singularizeInformationTypeSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }
  if (response === undefined || response === null || response.length === 0) throw new UserInputError(`Entity does not exist with ID ${id}`);

  let attachableObjects = {
		'categorizations': 'information-type-entry',
		'confidentiality_impact': 'impact-definition',
		'integrity_impact': 'impact-definition',
		'availability_impact': 'impact-definition',
    'information_types': 'information-type',
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
      singularizeSchema: singularizeInformationTypeSchema
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
  sparqlQuery = detachFromInformationTypeQuery(id, field, entityIri);
  try {
    response = await dataSources.Stardog.create({
      dbName,
      sparqlQuery,
      queryId: `Detach ${field} from Information Type`
      });
  } catch (e) {
    console.log(e)
    throw e
  }

  return true;
};


// Impact Definition
export const findImpactDefinitionById = async (id, dbName, dataSources, select) => {
  // ensure the id is a valid UUID
  if (!checkIfValidUUID(id)) throw new UserInputError(`Invalid identifier: ${id}`);

  let iri = `<http://cyio.darklight.ai/impact-definition--${id}>`;
  return findImpactDefinitionByIri(iri, dbName, dataSources, select);
}

export const findImpactDefinitionByIri = async (iri, dbName, dataSources, select) => {
  const sparqlQuery = selectImpactDefinitionByIriQuery(iri, select);
  let response;
  try {
    response = await dataSources.Stardog.queryById({
      dbName,
      sparqlQuery,
      queryId: "Select Impact Definition",
      singularizeSchema: singularizeImpactDefinitionSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }
  if (response === undefined || response === null || response.length === 0) return null;
  const reducer = getReducer("IMPACT-DEFINITION");
  return reducer(response[0]);  
};

export const findAllImpactDefinitionEntries = async (args, dbName, dataSources, select ) => {
  const sparqlQuery = selectAllImpactDefinitionsQuery(select, args);
  let response;
  try {
    response = await dataSources.Stardog.queryAll({
      dbName,
      sparqlQuery,
      queryId: "Select List of Impact Definitions",
      singularizeSchema: singularizeImpactDefinitionSchema
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
  const reducer = getReducer("IMPACT-DEFINITION");
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

export const createImpactDefinition = async (input, dbName, dataSources, selectMap) => {
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
  if (input.justification !== undefined ) {
    input.justification = input.justification.replace(/\s+/g, ' ')
																						.replace(/\n/g, '\\n')
																						.replace(/\"/g, '\\"')
																						.replace(/\'/g, "\\'")
																						.replace(/[\u2019\u2019]/g, "\\'")
																						.replace(/[\u201C\u201D]/g, '\\"');
  }

  // create the Impact Definition object
  let response;
  let {iri, id, query} = insertImpactDefinitionQuery(input);
  try {
    response = await dataSources.Stardog.create({
      dbName,
      sparqlQuery: query,
      queryId: "Create Impact Definition object"
      });
  } catch (e) {
    console.log(e)
    throw e
  }

  // retrieve the newly created Impact Definition to be returned
  const selectQuery = selectImpactDefinitionQuery(id, selectMap.getNode("createImpactDefinition"));
  let result;
  try {
    result = await dataSources.Stardog.queryById({
      dbName,
      sparqlQuery: selectQuery,
      queryId: "Select Impact Definition object",
      singularizeSchema: singularizeImpactDefinitionSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }
  if (result === undefined || result === null || result.length === 0) return null;
  const reducer = getReducer("IMPACT-DEFINITION");
  return reducer(result[0]);
};

export const deleteImpactDefinitionById = async ( id, dbName, dataSources, selectMap) => {
  let select = ['iri','id','object_type',];
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
    let sparqlQuery = selectImpactDefinitionQuery(itemId, select);
    try {
      response = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery,
        queryId: "Select Impact Definition",
        singularizeSchema: singularizeImpactDefinitionSchema
      });
    } catch (e) {
      console.log(e)
      throw e
    }
    if (response === undefined || response.length === 0) throw new UserInputError(`Entity does not exist with ID ${itemId}`);

    // Delete any associated confidentiality impact
    if (response[0].confidentiality_impact ) {
      let sparqlQuery = deleteImpactDefinitionByIriQuery(response[0].confidentiality_impact);
      try {
        let results = await dataSources.Stardog.delete({
          dbName,
          sparqlQuery,
          queryId: "Delete Confidentiality Impact Definition"
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
          dbName,
          sparqlQuery,
          queryId: "Delete Integrity Impact Definition"
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
          dbName,
          sparqlQuery,
          queryId: "Delete Availability Impact Definition"
        });
      } catch (e) {
        console.log(e)
        throw e
      }
    }

    sparqlQuery = deleteImpactDefinitionQuery(itemId);
    try {
      response = await dataSources.Stardog.delete({
        dbName,
        sparqlQuery,
        queryId: "Delete Impact Definition"
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

export const editImpactDefinitionById = async (id, input, dbName, dataSources, selectMap, schema) => {
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

  const sparqlQuery = selectImpactDefinitionQuery(id, editSelect );
  let response = await dataSources.Stardog.queryById({
    dbName,
    sparqlQuery,
    queryId: "Select Impact Definition",
    singularizeSchema: singularizeImpactDefinitionSchema
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

  // Handle the update to fields that have references to other object instances
  for (let editItem  of input) {
    if (editItem.operation === 'skip') continue;

    let value, fieldType, objectType, objArray, iris=[];
    for (value of editItem.value) {
      switch(editItem.key) {
				case 'base':
				case 'selected':
          if (!validateEnumValue(value, 'FIPS199', schema))
            throw new UserInputError(`Invalid value "${value}" for field "${editItem.key}".`);
          fieldType = 'simple';
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
          dbName,
          sparqlQuery,
          queryId: "Obtaining IRI for the object with id",
          singularizeSchema: singularizeImpactDefinitionSchema
        });
        if (result === undefined || result.length === 0) throw new UserInputError(`Entity does not exist with ID ${value}`);
        iris.push(`<${result[0].iri}>`);
      }
    }
    if (iris.length > 0) editItem.value = iris;
  }    

  const query = updateQuery(
    `http://cyio.darklight.ai/impact-definition--${id}`,
    "http://csrc.nist.gov/ns/oscal/info-system#ImpactDefinition",
    input,
    informationTypePredicateMap
  );
  if (query !== null) {
    let response;
    try {
      response = await dataSources.Stardog.edit({
        dbName,
        sparqlQuery: query,
        queryId: "Update Impact Definition"
      });  
    } catch (e) {
      console.log(e)
      throw e
    }
  }

  const selectQuery = selectImpactDefinitionQuery(id, selectMap.getNode("editImpactDefinition"));
  const result = await dataSources.Stardog.queryById({
    dbName,
    sparqlQuery: selectQuery,
    queryId: "Select Impact Definition",
    singularizeSchema: singularizeImpactDefinitionSchema
  });
  const reducer = getReducer("IMPACT-DEFINITION");
  return reducer(result[0]);
};

export const attachToImpactDefinition = async (id, field, entityId, dbName, dataSources, selectMap) => {
  let sparqlQuery;
  if (!checkIfValidUUID(id)) throw new UserInputError(`Invalid identifier: ${id}`);
  if (!checkIfValidUUID(entityId)) throw new UserInputError(`Invalid identifier: ${entityId}`);

  // check to see if the information system exists
  let iri = `<http://cyio.darklight.ai/impact-definition--${id}>`;
  sparqlQuery = selectImpactDefinitionByIriQuery(iri, select);
  let response;
  try {
    response = await dataSources.Stardog.queryById({
      dbName,
      sparqlQuery,
      queryId: "Select Impact Definition",
      singularizeSchema: singularizeImpactDefinitionSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }
  if (response === undefined || response === null || response.length === 0) throw new UserInputError(`Entity does not exist with ID ${id}`);

  let attachableObjects = {
		'categorizations': 'information-type-entry',
		'confidentiality_impact': 'impact-definition',
		'integrity_impact': 'impact-definition',
		'availability_impact': 'impact-definition',
    'information_types': 'information-type',
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
      singularizeSchema: singularizeImpactDefinitionSchema
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
  sparqlQuery = attachToImpactDefinitionQuery(id, field, entityIri);
  try {
    response = await dataSources.Stardog.create({
      dbName,
      sparqlQuery,
      queryId: `Attach ${field} to Impact Definition`
      });
  } catch (e) {
    console.log(e)
    throw e
  }

  return true;
};

export const detachFromImpactDefinition = async (id, field, entityId, dbName, dataSources, selectMap) => {
  let sparqlQuery;
  if (!checkIfValidUUID(id)) throw new UserInputError(`Invalid identifier: ${id}`);
  if (!checkIfValidUUID(entityId)) throw new UserInputError(`Invalid identifier: ${entityId}`);

  // check to see if the information system exists
  let iri = `<http://cyio.darklight.ai/impact-definition--${id}>`;
  sparqlQuery = selectImpactDefinitionByIriQuery(iri, select);
  let response;
  try {
    response = await dataSources.Stardog.queryById({
      dbName,
      sparqlQuery,
      queryId: "Select Impact Definition",
      singularizeSchema: singularizeImpactDefinitionSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }
  if (response === undefined || response === null || response.length === 0) throw new UserInputError(`Entity does not exist with ID ${id}`);

  let attachableObjects = {
		'categorizations': 'information-type-entry',
		'confidentiality_impact': 'impact-definition',
		'integrity_impact': 'impact-definition',
		'availability_impact': 'impact-definition',
    'information_types': 'information-type',
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
      singularizeSchema: singularizeImpactDefinitionSchema
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
  sparqlQuery = detachFromImpactDefinitionQuery(id, field, entityIri);
  try {
    response = await dataSources.Stardog.create({
      dbName,
      sparqlQuery,
      queryId: `Detach ${field} from Impact Definition`
      });
  } catch (e) {
    console.log(e)
    throw e
  }

  return true;
};
