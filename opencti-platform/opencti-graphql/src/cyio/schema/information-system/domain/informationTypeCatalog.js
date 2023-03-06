import { UserInputError } from 'apollo-server-errors';
import { compareValues, filterValues, updateQuery, checkIfValidUUID } from '../../utils.js';
import conf from '../../../../config/conf';
import { selectObjectIriByIdQuery } from '../../global/global-utils.js';
import { attachToSystemConfiguration, detachFromSystemConfiguration } from '../../system-configuration/domain/system-configuration.js';
import {
  getReducer,
  informationTypeCatalogPredicateMap,
  singularizeInformationTypeCatalogSchema,
  insertInformationTypeCatalogQuery,
  selectInformationTypeCatalogQuery,
  selectInformationTypeCatalogByIriQuery,
  selectAllInformationTypeCatalogsQuery,
  deleteInformationTypeCatalogQuery,
  attachToInformationTypeCatalogQuery,
  detachFromInformationTypeCatalogQuery,
  selectCatalogCategoriesQuery,
  selectCatalogCategoryMembersQuery,
  selectCatalogMemberQuery,
} from '../schema/sparql/informationTypeCatalog.js';
import {
  createInformationType,
  deleteInformationTypeById,
  editInformationTypeById
} from '../domain/informationType.js';
import {
  getReducer as getInformationTypeReducer,
  deleteInformationTypeByIriQuery,
  singularizeInformationTypeSchema,  
} from '../schema/sparql/informationType.js';


// Information Type Catalog
export const findInformationTypeCatalogById = async (id, dbName, dataSources, select) => {
  // ensure the id is a valid UUID
  if (!checkIfValidUUID(id)) throw new UserInputError(`Invalid identifier: ${id}`);

  let iri = `<http://cyio.darklight.ai/information-type-catalog--${id}>`;
  return findInformationTypeCatalogByIri(iri, dbName, dataSources, select);
}

export const findInformationTypeCatalogByIri = async (iri, dbName, dataSources, select) => {
  let contextDB = conf.get('app:database:context') || 'cyber-context';
  const sparqlQuery = selectInformationTypeCatalogByIriQuery(iri, select);
  let response;
  try {
    response = await dataSources.Stardog.queryById({
      dbName: contextDB,
      sparqlQuery,
      queryId: "Select Information Type Catalog",
      singularizeSchema: singularizeInformationTypeCatalogSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }

  if (response === undefined) return null;
  if (Array.isArray(response) && response.length > 0) {
    const reducer = getReducer("INFORMATION-TYPE-CATALOG");
    return reducer(response[0]);  
  }
};

export const findAllInformationTypeCatalogs = async (args, dbName, dataSources, select) => {
  let contextDB = conf.get('app:database:context') || 'cyber-context';
  const sparqlQuery = selectAllInformationTypeCatalogsQuery(select, args);
  let response;
  try {
    response = await dataSources.Stardog.queryAll({
      dbName: contextDB,
      sparqlQuery,
      queryId: "Select List of Configuration Information",
      singularizeSchema: singularizeInformationTypeCatalogSchema
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
  const reducer = getReducer("INFORMATION-TYPE-CATALOG");
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

export const createInformationTypeCatalog = async (input, dbName, dataSources, select) => {
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

  // create the Connection Information object
  let response;
  let {iri, id, query} = insertInformationTypeCatalogQuery(input);
  try {
    response = await dataSources.Stardog.create({
      dbName: contextDB,
      sparqlQuery: query,
      queryId: "Create Information Type Catalog object"
      });
  } catch (e) {
    console.log(e)
    throw e
  }

  // Attach the new Information Type Catalog to the System Configuration's information_type_catalogs
  await attachToSystemConfiguration(id, 'information-type-catalog', dataSources);

  // retrieve the newly created Information Type Catalog to be returned
  const selectQuery = selectInformationTypeCatalogQuery(id, select);
  response = await dataSources.Stardog.queryById({
    dbName: contextDB,
    sparqlQuery: selectQuery,
    queryId: "Select Connection Information object",
    singularizeSchema: singularizeInformationTypeCatalogSchema
  });
  const reducer = getReducer("INFORMATION-TYPE-CATALOG");
  return reducer(response[0]);
};

export const deleteInformationTypeCatalogById = async ( id, dbName, dataSources ) => {
  let contextDB = conf.get('app:database:context') || 'cyber-context';
  let select = ['id','object_type','catalog','entries'];
  let idArray = []
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
    let sparqlQuery = selectInformationTypeCatalogQuery(itemId, select);
    try {
      response = await dataSources.Stardog.queryById({
        dbName: contextDB,
        sparqlQuery,
        queryId: "Select Information Type Catalog",
        singularizeSchema: singularizeInformationTypeCatalogSchema
      });
    } catch (e) {
      console.log(e)
      throw e
    }
    if (response === undefined || response.length === 0) throw new UserInputError(`Entity does not exist with ID ${itemId}`);

    // Detach the Information Type Catalog to the System Configuration
    await detachFromSystemConfiguration(itemId, 'information-type-catalog', dataSources);

    // delete any entries in the Catalog
    if (response[0].entries !== undefined && response[0].entries !== null) {
      for (let entryIri of response[0].entries) {
        let query = deleteInformationTypeByIriQuery(entryIri);
        try {
          response = await dataSources.Stardog.delete({
            dbName: contextDB,
            sparqlQuery: query,
            queryId: "Delete Information Type in Catalog"
          });
        } catch (e) {
          console.log(e)
          throw e    
        }
      }
    }

    sparqlQuery = deleteInformationTypeCatalogQuery(itemId);
    try {
      response = await dataSources.Stardog.delete({
        dbName: contextDB,
        sparqlQuery,
        queryId: "Delete Information Type Catalog"
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

export const editInformationTypeCatalogById = async (id, input, dbName, dataSources, select, schema) => {
  let contextDB = conf.get('app:database:context') || 'cyber-context';
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

  const sparqlQuery = selectInformationTypeCatalogQuery(id, editSelect );
  let response = await dataSources.Stardog.queryById({
    dbName: contextDB,
    sparqlQuery,
    queryId: "Select Information Type Catalog",
    singularizeSchema: singularizeInformationTypeCatalogSchema
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

  // Push an edit to update the modified time of the object, if supported
  if (informationTypeCatalogPredicateMap.hasOwnProperty('modified')) {
    const timestamp = new Date().toISOString();
    if (!response[0].hasOwnProperty('created')) {
      let update = {key: "created", value:[`${timestamp}`], operation: "add"}
      input.push(update);
    }
    let operation = "replace";
    if (!response[0].hasOwnProperty('modified')) operation = "add";
    let update = {key: "modified", value:[`${timestamp}`], operation: `${operation}`}
    input.push(update);
  }

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

        // let iri = `${objectMap[objectType].iriTemplate}-${value}`;
        let sparqlQuery = selectObjectIriByIdQuery(value, objectType);
        let result = await dataSources.Stardog.queryById({
          dbName: contextDB,
          sparqlQuery,
          queryId: "Obtaining IRI for the object with id",
          singularizeSchema: singularizeInformationTypeCatalogSchema
        });
        if (result === undefined || result.length === 0) throw new UserInputError(`Entity does not exist with ID ${value}`);
        iris.push(`<${result[0].iri}>`);
      }
    }
    if (iris.length > 0) editItem.value = iris;
  }    

  const query = updateQuery(
    `http://cyio.darklight.ai/information-type-catalog--${id}`,
    "http://nist.gov/ns/sp800-60#InformationTypeCatalog",
    input,
    informationTypeCatalogPredicateMap
  );
  if (query !== null) {
    let response;
    try {
      response = await dataSources.Stardog.edit({
        dbName: contextDB,
        sparqlQuery: query,
        queryId: "Update Information Type Catalog"
      });  
    } catch (e) {
      console.log(e)
      throw e
    }
  }

  const selectQuery = selectInformationTypeCatalogQuery(id, select);
  const result = await dataSources.Stardog.queryById({
    dbName: contextDB,
    sparqlQuery: selectQuery,
    queryId: "Select Information Type Catalog",
    singularizeSchema: singularizeInformationTypeCatalogSchema
  });
  const reducer = getReducer("INFORMATION-TYPE-CATALOG");
  return reducer(result[0]);
};

export const createCatalogEntry = async (catalogId, input, dbName, dataSources, select) => {
  let contextDB = conf.get('app:database:context') || 'cyber-context';
  let sparqlQuery;
  let response;

  // check to make sure catalog ID is valid format
  if (!checkIfValidUUID(catalogId)) throw new UserInputError(`Invalid identifier: ${catalogId}`);

  // check if catalog with the specified id exists
  let selectCheck = ['id','object_type','catalog'];
  sparqlQuery = selectInformationTypeCatalogQuery(catalogId, selectCheck);
  try {
    response = await dataSources.Stardog.queryById({
      dbName: contextDB,
      sparqlQuery,
      queryId: "Select Information Type Catalog",
      singularizeSchema: singularizeInformationTypeCatalogSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }
  if (response === undefined || response.length === 0) throw new UserInputError(`Entity does not exist with ID ${catalogId}`);
  
  // create the Information Type
  response = await createInformationType(input, contextDB, dataSources, select)
  if (response === undefined || response.length === 0) throw new UserInputError(`Entity does not exist with ID ${catalogId}`);

  // attach the entity to the Information Type Catalog instance
  // response = await addInformationTypeToCatalog( catalogId, response[0].id, contextDB, dataSources);
  let iris = `<${response.iri}>`;
  sparqlQuery = attachToInformationTypeCatalogQuery(catalogId, 'entries', iris);
  await dataSources.Stardog.create({
    dbName: contextDB,
    sparqlQuery,
    queryId: 'Attaching to Information Type Catalog',
  });

  return response;
};

export const deleteCatalogEntry = async (catalogId, entryId, dbName, dataSources) => {
  let contextDB = conf.get('app:database:context') || 'cyber-context';
  let sparqlQuery;
  let response;

  // check to make sure catalog ID is valid format
  if (!checkIfValidUUID(catalogId)) throw new UserInputError(`Invalid identifier: ${catalogId}`);
  if (!checkIfValidUUID(entryId)) throw new UserInputError(`Invalid identifier: ${entryId}`);

  // check if catalog with the specified id exists
  let selectCheck = ['id','object_type','catalog'];
  sparqlQuery = selectInformationTypeCatalogQuery(catalogId, selectCheck);
  try {
    response = await dataSources.Stardog.queryById({
      dbName: contextDB,
      sparqlQuery,
      queryId: "Select Information Type Catalog",
      singularizeSchema: singularizeInformationTypeCatalogSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }
  if (response === undefined || response.length === 0) throw new UserInputError(`Entity does not exist with ID ${catalogId}`);
  
  // check to see if they entity to be deleted is an Information Type
  sparqlQuery = selectObjectIriByIdQuery(entryId, 'information-type');
  let result = await dataSources.Stardog.queryById({
    dbName: contextDB,
    sparqlQuery,
    queryId: "Obtaining IRI for object with id to attached",
    singularizeSchema: singularizeInformationTypeSchema
  });
  if (result === undefined || result.length === 0) throw new UserInputError(`Entity does not exist with ID ${entryId}`);
  let iris = `<${result[0].iri}>`;
  
  // attach the entity to the Information Type Catalog instance
  sparqlQuery = detachFromInformationTypeCatalogQuery(catalogId, 'entries', iris);
  await dataSources.Stardog.delete({
    dbName,
    sparqlQuery,
    queryId: 'Detaching to Information Type Catalog',
  });

  // delete the information type
  response = await deleteInformationTypeById(entryId, contextDB, dataSources);
  if (result === undefined || result.length === 0) throw new UserInputError(`Entity does not exist with ID ${entryId}`);
  return entryId;
};

export const editCatalogEntry = async (catalogId, entryId, input, dbName, dataSources, select) => {
  let contextDB = conf.get('app:database:context') || 'cyber-context';
  let sparqlQuery;
  let response;

  if (!checkIfValidUUID(catalogId)) throw new UserInputError(`Invalid identifier: ${id}`);  
  if (!checkIfValidUUID(entryId)) throw new UserInputError(`Invalid identifier: ${entryId}`);

  // check if catalog with the specified id exists
  let selectCheck = ['id','object_type','catalog'];
  sparqlQuery = selectInformationTypeCatalogQuery(catalogId, selectCheck);
  try {
    response = await dataSources.Stardog.queryById({
      dbName: contextDB,
      sparqlQuery,
      queryId: "Select Information Type Catalog",
      singularizeSchema: singularizeInformationTypeCatalogSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }
  if (response === undefined || response.length === 0) throw new UserInputError(`Entity does not exist with ID ${catalogId}`);
  
  // check to see if they entity to be attached is an Information Type
  sparqlQuery = selectObjectIriByIdQuery(entryId, 'information-type');
  let result = await dataSources.Stardog.queryById({
    dbName: contextDB,
    sparqlQuery,
    queryId: "Obtaining IRI for object with id to attached",
    singularizeSchema: singularizeInformationTypeSchema
  });
  if (result === undefined || result.length === 0) throw new UserInputError(`Entity does not exist with ID ${entryId}`);
  let iris = `<${result[0].iri}>`;

  response = await editInformationTypeById(entryId, input, dbName, dataSources, select, schema);
  if (result === undefined || result.length === 0) throw new UserInputError(`Entity does not exist with ID ${entryId}`);

  return response;
}

export const addInformationTypeToCatalog = async (id, entryId, dbName, dataSources) => {
  let contextDB = conf.get('app:database:context') || 'cyber-context';
  let sparqlQuery;

  if (!checkIfValidUUID(id)) throw new UserInputError(`Invalid identifier: ${id}`);  
  if (!checkIfValidUUID(entryId)) throw new UserInputError(`Invalid identifier: ${entryId}`);  
  
  // check to see if they entity to be attached is an Information Type
  sparqlQuery = selectObjectIriByIdQuery(entryId, 'information-type');
  let result = await dataSources.Stardog.queryById({
    dbName: contextDB,
    sparqlQuery,
    queryId: "Obtaining IRI for object with id to attached",
    singularizeSchema: singularizeInformationTypeSchema
  });
  if (result === undefined || result.length === 0) throw new UserInputError(`Entity does not exist with ID ${entryId}`);
  let iris = `<${result[0].iri}>`;

  // attach the entity to the Information Type Catalog instance
  sparqlQuery = attachToInformationTypeCatalogQuery(id, 'entries', iris);
  await dataSources.Stardog.create({
    dbName: contextDB,
    sparqlQuery,
    queryId: 'Attaching to Information Type Catalog',
  });
};

export const removeInformationTypeFromCatalog = async (id, entryId, dbName, dataSources) => {
  let contextDB = conf.get('app:database:context') || 'cyber-context';
  let sparqlQuery;

  if (!checkIfValidUUID(id)) throw new UserInputError(`Invalid identifier: ${id}`);  
  if (!checkIfValidUUID(id)) throw new UserInputError(`Invalid identifier: ${entryId}`);  

  // check to see if they entity to be attached is an Information Type
  sparqlQuery = selectObjectIriByIdQuery(entryId, 'information-type');
  let result = await dataSources.Stardog.queryById({
    dbName: contextDB,
    sparqlQuery,
    queryId: "Obtaining IRI for object with id to detached",
    singularizeSchema: singularizeInformationTypeSchema
  });
  if (result === undefined || result.length === 0) throw new UserInputError(`Entity does not exist with ID ${entryId}`);
  let iris = `<${result[0].iri}>`;
  
  // attach the entity to the Information Type Catalog instance
  sparqlQuery = detachFromInformationTypeCatalogQuery(id, 'entries', iris);
  await dataSources.Stardog.delete({
    dbName,
    sparqlQuery,
    queryId: 'Detaching to Information Type Catalog',
  });
};

export const fetchCatalogCategories = async (id, dbName, dataSources) => {
  // ensure the id is a valid UUID
  if (!checkIfValidUUID(id)) throw new UserInputError(`Invalid identifier: ${id}`);

  let contextDB = conf.get('app:database:context') || 'cyber-context';
  let sparqlQuery;
  let response;

  // check if catalog with the specified id exists
  let selectCheck = ['id','object_type','catalog'];
  sparqlQuery = selectInformationTypeCatalogQuery(id, selectCheck);
  try {
    response = await dataSources.Stardog.queryById({
      dbName: contextDB,
      sparqlQuery,
      queryId: "Select Information Type Catalog",
      singularizeSchema: singularizeInformationTypeCatalogSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }
  if (response === undefined || response.length === 0) throw new UserInputError(`Entity does not exist with ID ${id}`);

  // retrieve the list of categories
  sparqlQuery = selectCatalogCategoriesQuery(id);
  try {
    response = await dataSources.Stardog.queryById({
      dbName: contextDB,
      sparqlQuery,
      queryId: "Select Information Type Catalog Categories",
      singularizeSchema: singularizeInformationTypeCatalogSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }
  if (response === undefined || response.length === 0) throw new UserInputError(`Entity does not exist with ID ${id}`);
  if (response[0].category) return response[0].category;
  return [];
};

export const fetchCategoryMembers = async (id, categoryName, dbName, dataSources, select) => {
  // ensure the id is a valid UUID
  if (!checkIfValidUUID(id)) throw new UserInputError(`Invalid identifier: ${id}`);

  let contextDB = conf.get('app:database:context') || 'cyber-context';
  let sparqlQuery;
  let response;

  // check if catalog with the specified id exists
  let selectCheck = ['id','object_type','catalog'];
  sparqlQuery = selectInformationTypeCatalogQuery(id, selectCheck);
  try {
    response = await dataSources.Stardog.queryById({
      dbName: contextDB,
      sparqlQuery,
      queryId: "Select Information Type Catalog",
      singularizeSchema: singularizeInformationTypeCatalogSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }
  if (response === undefined || response.length === 0) throw new UserInputError(`Entity does not exist with ID ${catalogId}`);

  // retrieve the members of the category
  sparqlQuery = selectCatalogCategoryMembersQuery(id, categoryName, select);
  try {
    response = await dataSources.Stardog.queryById({
      dbName: contextDB,
      sparqlQuery,
      queryId: "Select Members of a Category in Information Type Catalog",
      singularizeSchema: singularizeInformationTypeSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }

  const reducer = getInformationTypeReducer("INFORMATION-TYPE");
  let results = []
  for (let result of response ) {
    if (select.includes('display_name')) {
      let display_name = (result.identifier ? result.identifier : '') + "  " +
                          (result.title ? result.title : '');
      display_name = display_name.trim();
      if (display_name.length > 0) result.display_name = display_name;
    }
  
    results.push(reducer(result))
  }

  return results;
};

export const fetchInformationTypeFromCatalog = async (id, infoTypeId, dbName, dataSources, select) => {
  // ensure the id is a valid UUID
  if (!checkIfValidUUID(id)) throw new UserInputError(`Invalid identifier: ${id}`);
  if (!checkIfValidUUID(infoTypeId)) throw new UserInputError(`Invalid identifier: ${infoTypeId}`);

  let contextDB = conf.get('app:database:context') || 'cyber-context';
  let sparqlQuery;
  let response;

  // check if catalog with the specified id exists
  let selectCheck = ['id','object_type','catalog'];
  sparqlQuery = selectInformationTypeCatalogQuery(id, selectCheck);
  try {
    response = await dataSources.Stardog.queryById({
      dbName: contextDB,
      sparqlQuery,
      queryId: "Select Information Type Catalog",
      singularizeSchema: singularizeInformationTypeCatalogSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }
  if (response === undefined || response.length === 0) throw new UserInputError(`Entity does not exist with ID ${catalogId}`);

    // retrieve the specific member from the category
    sparqlQuery = selectCatalogMemberQuery(id, infoTypeId, select);
    try {
      response = await dataSources.Stardog.queryById({
        dbName: contextDB,
        sparqlQuery,
        queryId: "Select specific member in Information Type Catalog",
        singularizeSchema: singularizeInformationTypeSchema
      });
    } catch (e) {
      console.log(e)
      throw e
    }
  
  const reducer = getInformationTypeReducer("INFORMATION-TYPE");
  let result = response[0];
  if (select.includes('display_name')) {
    let display_name = (result.identifier ? result.identifier : '') + "  " +
                        (result.title ? result.title : '');
    display_name = display_name.trim();
    if (display_name.length > 0) result.display_name = display_name;
  }
  return reducer(result);
};