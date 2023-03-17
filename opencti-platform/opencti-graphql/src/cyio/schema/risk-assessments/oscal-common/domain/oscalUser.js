import { UserInputError } from 'apollo-server-errors';
import conf from '../../../../../config/conf.js';
import { compareValues, filterValues, updateQuery, checkIfValidUUID, validateEnumValue } from '../../../utils.js';
import { selectObjectIriByIdQuery } from '../../../global/global-utils.js';
import {
  getReducer,
	// OSCAL User
  oscalUserPredicateMap,
  singularizeOscalUserSchema,
  selectOscalUserQuery,
  selectOscalUserByIriQuery,
  selectAllOscalUsersQuery,
  insertOscalUserQuery,
  deleteOscalUserQuery,
  deleteOscalUserByIriQuery,
  attachToOscalUserQuery,
  detachFromOscalUserQuery,
	// Authorized Privilege
  authorizedPrivilegePredicateMap,
  singularizeAuthorizedPrivilegeSchema,
  selectAuthorizedPrivilegeQuery,
  selectAuthorizedPrivilegeByIriQuery,
  selectAllAuthorizedPrivilegesQuery,
  insertAuthorizedPrivilegeQuery,
  deleteAuthorizedPrivilegeQuery,
  deleteAuthorizedPrivilegeByIriQuery,
  attachToAuthorizedPrivilegeQuery,
  detachFromAuthorizedPrivilegeQuery,
} from '../schema/sparql/oscalUser.js';


// Oscal User
export const findUserTypeById = async (id, dbName, dataSources, select) => {
  // ensure the id is a valid UUID
  if (!checkIfValidUUID(id)) throw new UserInputError(`Invalid identifier: ${id}`);

  let iri = `<http://cyio.darklight.ai/oscal-user--${id}>`;
  return findUserTypeByIri(iri, dbName, dataSources, select);
}

export const findUserTypeByIri = async (iri, dbName, dataSources, select) => {
  const sparqlQuery = selectOscalUserByIriQuery(iri, select);
  let response;
  try {
    response = await dataSources.Stardog.queryById({
      dbName,
      sparqlQuery,
      queryId: "Select Oscal User",
      singularizeSchema: singularizeOscalUserSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }
  if (response === undefined || response === null || response.length === 0) return null;
  const reducer = getReducer("OSCAL-USER");
  return reducer(response[0]);  
};

export const findAllUserTypes = async (args, dbName, dataSources, select ) => {
  const sparqlQuery = selectAllOscalUsersQuery(select, args);
  let response;
  try {
    response = await dataSources.Stardog.queryAll({
      dbName,
      sparqlQuery,
      queryId: "Select List of Oscal User types",
      singularizeSchema: singularizeOscalUserSchema
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
  const reducer = getReducer("OSCAL-USER");
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

export const createUserType = async (input, dbName, dataSources, select) => {
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
  if (input.name !== undefined ) {
    input.name = input.name.replace(/\s+/g, ' ')
                            .replace(/\n/g, '\\n')
                            .replace(/\"/g, '\\"')
                            .replace(/\'/g, "\\'")
                            .replace(/[\u2019\u2019]/g, "\\'")
                            .replace(/[\u201C\u201D]/g, '\\"');
  }
  if (input.short_name !== undefined ) {
    input.short_name = input.short_name.replace(/\s+/g, ' ')
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
		'authorized_privileges': { values: input.authorized_privileges, props: {}, objectType: 'authorized-privilege', insertFunction: insertAuthorizedPrivilegeQuery} ,
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
    if (input[fieldName]) delete input[fieldName];
  }

  // Collect all the referenced objects and remove them from input array
  let objectReferences = {
    'roles': { ids: input.roles, objectType: 'oscal-role' },
  };
  if (input.roles) delete input.roles;
  
  // create the Oscal User Type object
  let response;
  let {iri, id, query} = insertOscalUserQuery(input);
  try {
    response = await dataSources.Stardog.create({
      dbName,
      sparqlQuery: query,
      queryId: "Create Oscal User Type object"
      });
  } catch (e) {
    console.log(e)
    throw e
  }

  // Attach any nested definitions
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
      let attachQuery = attachToOscalUserQuery(id, key, itemIri );
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
        singularizeSchema: singularizeOscalUserSchema
      });
      if (result === undefined || result.length === 0) throw new UserInputError(`Entity does not exist with ID ${refId}`);
      iris.push(`<${result[0].iri}>`);
    }

    if (iris.length > 0) {
      // attach the definition to the new Information Type
      let attachQuery = attachToOscalUserQuery(id, key, iris );
      try {
        response = await dataSources.Stardog.create({
          dbName,
          sparqlQuery: attachQuery,
          queryId: `Attaching one or more ${itemName} to OSCAL User type`
          });
      } catch (e) {
        console.log(e)
        throw e
      }
    }
  }

  // retrieve the newly created Information Type to be returned
  const selectQuery = selectOscalUserQuery(id, select);
  let result;
  try {
    result = await dataSources.Stardog.queryById({
      dbName,
      sparqlQuery: selectQuery,
      queryId: "Select OSCAL User Type object",
      singularizeSchema: singularizeOscalUserSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }
  if (result === undefined || result === null || result.length === 0) return null;
  const reducer = getReducer("OSCAL-USER");
  return reducer(result[0]);
};

export const deleteUserTypeById = async ( id, dbName, dataSources ) => {
  let select = ['iri','id','object_type','roles','authorized_privileges'];
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
    let sparqlQuery = selectOscalUserQuery(itemId, select);
    try {
      response = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery,
        queryId: "Select OSCAL User Type",
        singularizeSchema: singularizeOscalUserSchema
      });
    } catch (e) {
      console.log(e)
      throw e
    }
    if (response === undefined || response.length === 0) throw new UserInputError(`Entity does not exist with ID ${itemId}`);

    // Delete any associated authorized privileges
    if (response[0].authorized_privileges ) {
      for (let iri of response[0].authorized_privileges) {
        let sparqlQuery = deleteOscalUserByIriQuery(iri);
        try {
          let results = await dataSources.Stardog.delete({
            dbName,
            sparqlQuery,
            queryId: "Delete authorized privileges"
          });
        } catch (e) {
          console.log(e)
          throw e
        }  
      }
    }

    sparqlQuery = deleteOscalUserQuery(itemId);
    try {
      response = await dataSources.Stardog.delete({
        dbName,
        sparqlQuery,
        queryId: "Delete OSCAL User type"
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

export const editUserTypeById = async ( id, input, dbName, dataSources, select, schema ) => {
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

  const sparqlQuery = selectOscalUserQuery(id, editSelect );
  let response = await dataSources.Stardog.queryById({
    dbName,
    sparqlQuery,
    queryId: "Select OSCAL User Type",
    singularizeSchema: singularizeOscalUserSchema
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
        case 'user_type':
          if (!validateEnumValue(value, 'UserType', schema))
            throw new UserInputError(`Invalid value "${value}" for field "${editItem.key}".`);
          fieldType = 'simple';
          break;
        case 'privilege_level':
          if (!validateEnumValue(value, 'PrivilegeLevel', schema))
            throw new UserInputError(`Invalid value "${value}" for field "${editItem.key}".`);
          fieldType = 'simple';
          break;
        case 'roles':
          objectType = 'oscal-role';
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
        case 'authorized_privileges':
          if (editItem.operation !== 'add') {
            // find the existing update entity in Information Type
            if (editItem.key in response[0]) {
              let entityIri;
              if (editItem.key === 'authorized_privileges') entityIri = response[0].authorized_privileges;

              // detach the private authorized privilege
              let query = detachFromOscalUserQuery(id, editItem.key, entityIri);
              await dataSources.Stardog.delete({
                dbName,
                sparqlQuery: query,
                queryId: "Detach authorized privilege"
              });

              // Delete the authorized privilege object since its private to the OSCAL User type
              query = deleteAuthorizedPrivilegeByIriQuery(entityIri);
              await dataSources.Stardog.delete({
                dbName,
                sparqlQuery: query,
                queryId: "Delete Authorized Privilege"
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

            // create the instance of the Impact Level
            const { iri: authPrivIri, id: authPrivId, query } = insertAuthorizedPrivilegeQuery(entity);
            await dataSources.Stardog.create({
              dbName,
              sparqlQuery: query,
              queryId: "Create authorized privilege of OSCAL User type"
            });

            // attach the new Impact Level to the Information Type Entry
            let attachQuery = attachToOscalUserQuery(id, editItem.key, authPrivIri);
            await dataSources.Stardog.create({
              dbName,
              sparqlQuery: attachQuery,
              queryId: "Attach authorized privilege object to OSCAL User Type"
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

        let sparqlQuery = selectObjectIriByIdQuery(value, objectType);
        let result = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: "Obtaining IRI for the object with id",
          singularizeSchema: singularizeOscalUserSchema
        });
        if (result === undefined || result.length === 0) throw new UserInputError(`Entity does not exist with ID ${value}`);
        iris.push(`<${result[0].iri}>`);
      }
    }
    if (iris.length > 0) editItem.value = iris;
  }    

  const query = updateQuery(
    `http://cyio.darklight.ai/oscal-user--${id}`,
    "http://csrc.nist.gov/ns/oscal/common#User",
    input,
    oscalUserPredicateMap
  );
  if (query !== null) {
    let response;
    try {
      response = await dataSources.Stardog.edit({
        dbName,
        sparqlQuery: query,
        queryId: "Update OSCAL User Type"
      });  
    } catch (e) {
      console.log(e)
      throw e
    }
  }

  const selectQuery = selectOscalUserQuery(id, select);
  const result = await dataSources.Stardog.queryById({
    dbName,
    sparqlQuery: selectQuery,
    queryId: "Select OSCAL User Type",
    singularizeSchema: singularizeOscalUserSchema
  });
  const reducer = getReducer("OSCAL-USER");
  return reducer(result[0]);
};

export const attachToUserType = async ( id, field, entityId, dbName, dataSources ) => {
  let sparqlQuery;
  if (!checkIfValidUUID(id)) throw new UserInputError(`Invalid identifier: ${id}`);
  if (!checkIfValidUUID(entityId)) throw new UserInputError(`Invalid identifier: ${entityId}`);

  // check to see if the OSCAL User exists
  let select = ['id','iri','object_type'];
  let iri = `<http://cyio.darklight.ai/oscal-user--${id}>`;
  sparqlQuery = selectOscalUserByIriQuery(iri, select);
  let response;
  try {
    response = await dataSources.Stardog.queryById({
      dbName,
      sparqlQuery,
      queryId: "Select OSCAL User type",
      singularizeSchema: singularizeOscalUserSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }
  if (response === undefined || response === null || response.length === 0) throw new UserInputError(`Entity does not exist with ID ${id}`);

  let attachableObjects = {
		'roles': 'oscal-role',
		'authorized_privileges': 'authorized-privilege',
    'object_markings': 'marking-definition',
    'labels': 'label',
    'links': 'link',
    'remarks': 'remark'
  }
  let objectType = attachableObjects[field];
  try {
    // check to see if the entity exists
    sparqlQuery = selectObjectIriByIdQuery(entityId, objectType);
    response = await dataSources.Stardog.queryById({
      dbName: (objectType === 'marking-definition' ? conf.get('app:config:db_name') || 'cyio-config' : dbName),
      sparqlQuery,
      queryId: "Obtaining IRI for the object with id",
      singularizeSchema: singularizeOscalUserSchema
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

  // Attach the object to the User
  sparqlQuery = attachToOscalUserQuery(id, field, entityIri);
  try {
    response = await dataSources.Stardog.create({
      dbName,
      sparqlQuery,
      queryId: `Attach ${field} to OSCAL User Type`
      });
  } catch (e) {
    console.log(e)
    throw e
  }

  return true;
};

export const detachFromUserType = async ( id, field, entityId, dbName, dataSources ) => {
  let sparqlQuery;
  if (!checkIfValidUUID(id)) throw new UserInputError(`Invalid identifier: ${id}`);
  if (!checkIfValidUUID(entityId)) throw new UserInputError(`Invalid identifier: ${entityId}`);

  // check to see if the OSCAL User exists
  let select = ['id','iri','object_type'];
  let iri = `<http://cyio.darklight.ai/oscal-user--${id}>`;
  sparqlQuery = selectOscalUserByIriQuery(iri, select);
  let response;
  try {
    response = await dataSources.Stardog.queryById({
      dbName,
      sparqlQuery,
      queryId: "Select OSCAL User Type",
      singularizeSchema: singularizeOscalUserSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }
  if (response === undefined || response === null || response.length === 0) throw new UserInputError(`Entity does not exist with ID ${id}`);

  let attachableObjects = {
		'roles': 'oscal-role',
		'authorized_privileges': 'authorized-privilege',
    'object_markings': 'marking-definition',
    'labels': 'label',
    'links': 'link',
    'remarks': 'remark'
  }
  let objectType = attachableObjects[field];
  try {
    // check to see if the entity exists
    sparqlQuery = selectObjectIriByIdQuery(entityId, objectType);
    response = await dataSources.Stardog.queryById({
      dbName: (objectType === 'marking-definition' ? conf.get('app:config:db_name') || 'cyio-config' : dbName),
      sparqlQuery,
      queryId: "Obtaining IRI for the object with id",
      singularizeSchema: singularizeOscalUserSchema
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

  // Attach the object to the OSCAL User
  sparqlQuery = detachFromOscalUserQuery(id, field, entityIri);
  try {
    response = await dataSources.Stardog.create({
      dbName,
      sparqlQuery,
      queryId: `Detach ${field} from OSCAL User Type`
      });
  } catch (e) {
    console.log(e)
    throw e
  }

  return true;
};


// Authorized Privilege
export const findAuthorizedPrivilegeById = async (id, dbName, dataSources, select) => {
  // ensure the id is a valid UUID
  if (!checkIfValidUUID(id)) throw new UserInputError(`Invalid identifier: ${id}`);

  let iri = `<http://cyio.darklight.ai/authorized-privilege--${id}>`;
  return findAuthorizedPrivilegeByIri(iri, dbName, dataSources, select);
}

export const findAuthorizedPrivilegeByIri = async (iri, dbName, dataSources, select) => {
  const sparqlQuery = selectAuthorizedPrivilegeByIriQuery(iri, select);
  let response;
  try {
    response = await dataSources.Stardog.queryById({
      dbName,
      sparqlQuery,
      queryId: "Select Authorized Privilege",
      singularizeSchema: singularizeAuthorizedPrivilegeSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }
  if (response === undefined || response === null || response.length === 0) return null;
  const reducer = getReducer("AUTHORIZED-PRIVILEGE");
  return reducer(response[0]);  
};

export const findAllAuthorizedPrivilegeEntries = async (args, dbName, dataSources, select ) => {
  const sparqlQuery = selectAllAuthorizedPrivilegesQuery(select, args);
  let response;
  try {
    response = await dataSources.Stardog.queryAll({
      dbName,
      sparqlQuery,
      queryId: "Select List of Authorized Privileges",
      singularizeSchema: singularizeAuthorizedPrivilegeSchema
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
  const reducer = getReducer("AUTHORIZED-PRIVILEGE");
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

export const createAuthorizedPrivilege = async (input, dbName, dataSources, select) => {
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

  // create the Impact Level object
  let response;
  let {iri, id, query} = insertAuthorizedPrivilegeQuery(input);
  try {
    response = await dataSources.Stardog.create({
      dbName,
      sparqlQuery: query,
      queryId: "Create authorized privilege"
      });
  } catch (e) {
    console.log(e)
    throw e
  }

  // retrieve the newly created Impact Level to be returned
  const selectQuery = selectAuthorizedPrivilegeQuery(id, select);
  let result;
  try {
    result = await dataSources.Stardog.queryById({
      dbName,
      sparqlQuery: selectQuery,
      queryId: "Select authorized privilege",
      singularizeSchema: singularizeAuthorizedPrivilegeSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }
  if (result === undefined || result === null || result.length === 0) return null;
  const reducer = getReducer("AUTHORIZED-PRIVILEGE");
  return reducer(result[0]);
};

export const deleteAuthorizedPrivilegeById = async ( id, dbName, dataSources, selectMap) => {
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
    let sparqlQuery = selectAuthorizedPrivilegeQuery(itemId, select);
    try {
      response = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery,
        queryId: "Select authorized privilege",
        singularizeSchema: singularizeAuthorizedPrivilegeSchema
      });
    } catch (e) {
      console.log(e)
      throw e
    }
    if (response === undefined || response.length === 0) throw new UserInputError(`Entity does not exist with ID ${itemId}`);

    sparqlQuery = deleteAuthorizedPrivilegeQuery(itemId);
    try {
      response = await dataSources.Stardog.delete({
        dbName,
        sparqlQuery,
        queryId: "Delete authorized privilege"
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

export const editAuthorizedPrivilegeById = async (id, input, dbName, dataSources, select, schema) => {
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

  const sparqlQuery = selectAuthorizedPrivilegeQuery(id, editSelect );
  let response = await dataSources.Stardog.queryById({
    dbName,
    sparqlQuery,
    queryId: "Select authorized privilege",
    singularizeSchema: singularizeAuthorizedPrivilegeSchema
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
          singularizeSchema: singularizeAuthorizedPrivilegeSchema
        });
        if (result === undefined || result.length === 0) throw new UserInputError(`Entity does not exist with ID ${value}`);
        iris.push(`<${result[0].iri}>`);
      }
    }
    if (iris.length > 0) editItem.value = iris;
  }    

  const query = updateQuery(
    `http://cyio.darklight.ai/authorized-privilege--${id}`,
    "http://csrc.nist.gov/ns/oscal/common#AuthorizedPrivilege",
    input,
    authorizedPrivilegePredicateMap
  );
  if (query !== null) {
    let response;
    try {
      response = await dataSources.Stardog.edit({
        dbName,
        sparqlQuery: query,
        queryId: "Update authorized privilege"
      });  
    } catch (e) {
      console.log(e)
      throw e
    }
  }

  const selectQuery = selectAuthorizedPrivilegeQuery(id, select);
  const result = await dataSources.Stardog.queryById({
    dbName,
    sparqlQuery: selectQuery,
    queryId: "Select authorized privilege",
    singularizeSchema: singularizeAuthorizedPrivilegeSchema
  });
  const reducer = getReducer("AUTHORIZED-PRIVILEGE");
  return reducer(result[0]);
};

export const attachToAuthorizedPrivilege = async (id, field, entityId, dbName, dataSources, selectMap) => {
  let sparqlQuery;
  if (!checkIfValidUUID(id)) throw new UserInputError(`Invalid identifier: ${id}`);
  if (!checkIfValidUUID(entityId)) throw new UserInputError(`Invalid identifier: ${entityId}`);

  // check to see if the authorized privilege exists
  let iri = `<http://cyio.darklight.ai/authorized-privilege--${id}>`;
  sparqlQuery = selectAuthorizedPrivilegeByIriQuery(iri, select);
  let response;
  try {
    response = await dataSources.Stardog.queryById({
      dbName,
      sparqlQuery,
      queryId: "Select authorized privilege",
      singularizeSchema: singularizeAuthorizedPrivilegeSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }
  if (response === undefined || response === null || response.length === 0) throw new UserInputError(`Entity does not exist with ID ${id}`);

  let attachableObjects = {
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
      singularizeSchema: singularizeAuthorizedPrivilegeSchema
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

  // Attach the object to the authorized privilege
  sparqlQuery = attachToAuthorizedPrivilegeQuery(id, field, entityIri);
  try {
    response = await dataSources.Stardog.create({
      dbName,
      sparqlQuery,
      queryId: `Attach ${field} to authorized privilege`
      });
  } catch (e) {
    console.log(e)
    throw e
  }

  return true;
};

export const detachFromAuthorizedPrivilege = async (id, field, entityId, dbName, dataSources, selectMap) => {
  let sparqlQuery;
  if (!checkIfValidUUID(id)) throw new UserInputError(`Invalid identifier: ${id}`);
  if (!checkIfValidUUID(entityId)) throw new UserInputError(`Invalid identifier: ${entityId}`);

  // check to see if the OSCAL User exists
  let iri = `<http://cyio.darklight.ai/authorized-privilege--${id}>`;
  sparqlQuery = selectAuthorizedPrivilegeByIriQuery(iri, select);
  let response;
  try {
    response = await dataSources.Stardog.queryById({
      dbName,
      sparqlQuery,
      queryId: "Select authorized privilege",
      singularizeSchema: singularizeAuthorizedPrivilegeSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }
  if (response === undefined || response === null || response.length === 0) throw new UserInputError(`Entity does not exist with ID ${id}`);

  let attachableObjects = {
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
      singularizeSchema: singularizeAuthorizedPrivilegeSchema
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

  // Attach the object to the authorized privilege
  sparqlQuery = detachFromAuthorizedPrivilegeQuery(id, field, entityIri);
  try {
    response = await dataSources.Stardog.create({
      dbName,
      sparqlQuery,
      queryId: `Detach ${field} from authorized privilege`
      });
  } catch (e) {
    console.log(e)
    throw e
  }

  return true;
};
