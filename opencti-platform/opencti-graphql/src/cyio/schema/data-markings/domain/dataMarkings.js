import { UserInputError } from 'apollo-server-errors';
import {
  validateEnumValue,
  compareValues,
  filterValues,
  updateQuery,
  checkIfValidUUID,
} from '../../utils.js';
import conf from '../../../../config/conf';
import {
  getReducer,
  dataMarkingPredicateMap,
  granularDataMarkingPredicateMap,
  singularizeSchema,
  deleteDataMarkingQuery,
  deleteDataMarkingByIriQuery,
  deleteMultipleDataMarkingsQuery,
  insertDataMarkingQuery,
  selectAllDataMarkingsQuery,
  selectDataMarkingQuery,
  selectDataMarkingByIriQuery,
  attachToDataMarkingQuery,
  detachFromDataMarkingQuery,
} from '../schema/sparql/dataMarkings.js';

export const findAllDataMarkings = async (args, dbName, dataSources, selectMap) => {
  const sparqlQuery = selectAllDataMarkingsQuery(null, args);
  const configDB = conf.get('app:config:db_name') || 'cyio-config';
  let response;
  try {
    response = await dataSources.Stardog.queryAll({
      dbName: 'cyio-config',
      sparqlQuery,
      queryId: 'Select List of Data Marking',
      singularizeSchema,
    });
  } catch (e) {
    console.log(e);
    throw e;
  }

  // no results found
  if (response === undefined || response.length === 0) return null;

  // Handle reporting Stardog Error
  if (typeof response === 'object' && 'body' in response) {
    throw new UserInputError(response.statusText, {
      error_details: response.body.message ? response.body.message : response.body,
      error_code: response.body.code ? response.body.code : 'N/A',
    });
  }

  // if no matching results, then return null
  if (Array.isArray(response) && response.length < 1) return null;

  const edges = [];
  const reducer = getReducer('DATA-MARKING');
  const skipCount = 0;
  let filterCount = 0;
  let resultCount = 0;
  let limit;
  let offset;
  let limitSize;
  let offsetSize;
  limitSize = limit = args.first === undefined ? response.length : args.first;
  offsetSize = offset = args.offset === undefined ? 0 : args.offset;

  let resultList;
  if (args.orderedBy !== undefined) {
    resultList = response.sort(compareValues(args.orderedBy, args.orderMode));
  } else {
    resultList = response;
  }

  // return null if offset value beyond number of results items
  if (offset > resultList.length) return null;

  // for each result in the result set
  for (const resultItem of resultList) {
    // skip down past the offset
    if (offset) {
      offset--;
      continue;
    }

    // filter out non-matching entries if a filter is to be applied
    if ('filters' in args && args.filters != null && args.filters.length > 0) {
      if (!filterValues(resultItem, args.filters, args.filterMode)) {
        continue;
      }
      filterCount++;
    }

    // if haven't reached limit to be returned
    if (limit) {
      const edge = {
        cursor: resultItem.iri,
        node: reducer(resultItem),
      };
      edges.push(edge);
      limit--;
      if (limit === 0) break;
    }
  }
  // check if there is data to be returned
  if (edges.length === 0) return null;
  let hasNextPage = false;
  let hasPreviousPage = false;
  resultCount = resultList.length - skipCount;
  if (edges.length < resultCount) {
    if (edges.length === limitSize && filterCount <= limitSize) {
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
      endCursor: edges[edges.length - 1].cursor,
      hasNextPage,
      hasPreviousPage,
      globalCount: resultCount,
    },
    edges,
  };
};

export const findDataMarkingById = async (id, dbName, dataSources, selectMap) => {
  const iri = `<http://cyio.darklight.ai/marking-definition--${id}>`;
  return findDataMarkingByIri(iri, dbName, dataSources, selectMap);
};

export const findDataMarkingByIri = async (iri, dbName, dataSources, selectMap) => {
  const sparqlQuery = selectDataMarkingByIriQuery(iri, selectMap.getNode('dataMarking'));
  let response;
  try {
    response = await dataSources.Stardog.queryById({
      dbName: 'cyio-config',
      sparqlQuery,
      queryId: 'Select Data Marking',
      singularizeSchema,
    });
  } catch (e) {
    console.log(e);
    throw e;
  }

  if (response === undefined) return null;
  if (typeof response === 'object' && 'body' in response) {
    throw new UserInputError(response.statusText, {
      error_details: response.body.message ? response.body.message : response.body,
      error_code: response.body.code ? response.body.code : 'N/A',
    });
  }

  if (Array.isArray(response) && response.length > 0) {
    const reducer = getReducer('DATA-MARKING');
    return reducer(response[0]);
  }
};

export const createDataMarking = async (input, dbName, selectMap, dataSources) => {
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

  // check if object with id exists
  // TODO: need to generate the iri or id
  const sparqlQuery = selectDataMarkingQuery(id, ['id', 'created', 'modified', 'name']);
  let response;
  try {
    response = await dataSources.Stardog.queryById({
      dbName: 'cyio-config',
      sparqlQuery,
      queryId: 'Checking if Data Marking already exists',
      singularizeSchema,
    });
  } catch (e) {
    console.log(e);
    throw e;
  }
  if (response !== undefined && response.length > 0)
    throw new UserInputError(`Data Marking already exists with the name "${results[0].name}"`);

  // create the Data Marking
  let { iri, id, query } = insertDataMarkingQuery(input);
  try {
    response = await dataSources.Stardog.create({
      dbName: 'cyio-config',
      sparqlQuery: query,
      queryId: 'Create Data Marking',
    });
  } catch (e) {
    console.log(e);
    throw e;
  }

  // retrieve the newly created Data Marking to be returned
  const select = selectDataMarkingQuery(id, selectMap.getNode('createDataMarking'));
  const result = await dataSources.Stardog.queryById({
    dbName: 'cyio-config',
    sparqlQuery: select,
    queryId: 'Select Data Marking',
    singularizeSchema,
  });
  const reducer = getReducer('DATA-MARKING');
  return reducer(result[0]);
};

export const deleteDataMarkingById = async (id, dbName, dataSources) => {
  const select = ['id', 'object_type'];
  if (!Array.isArray(id)) {
    if (!checkIfValidUUID(id)) throw new UserInputError(`Invalid identifier: ${id}`);

    // check if object with id exists
    let sparqlQuery = selectDataMarkingQuery(id, select);
    let response;
    try {
      response = await dataSources.Stardog.queryById({
        dbName: 'cyio-config',
        sparqlQuery,
        queryId: 'Select Data Marking',
        singularizeSchema,
      });
    } catch (e) {
      console.log(e);
      throw e;
    }
    if (response === undefined || response.length === 0) throw new UserInputError(`Entity does not exist with ID ${id}`);

    // delete the object
    sparqlQuery = deleteDataMarkingQuery(id);
    try {
      response = await dataSources.Stardog.delete({
        dbName: 'cyio-config',
        sparqlQuery,
        queryId: 'Delete Data Marking',
      });
    } catch (e) {
      console.log(e);
      throw e;
    }

    if (response === undefined || response.length === 0) throw new UserInputError(`Entity does not exist with ID ${id}`);
    return id;
  }

  if (Array.isArray(id)) {
    let response;
    for (const item of id) {
      if (!checkIfValidUUID(item)) throw new UserInputError(`Invalid identifier: ${item}`);

      // check if object with id exists
      const sparqlQuery = selectDataMarkingQuery(id, select);
      try {
        response = await dataSources.Stardog.queryById({
          dbName: 'cyio-config',
          sparqlQuery,
          queryId: 'Select Data Marking',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }

      if (response === undefined || response.length === 0) throw new UserInputError(`Entity does not exist with ID ${id}`);
    }

    const sparqlQuery = deleteMultipleDataMarkingsQuery(id);
    try {
      response = await dataSources.Stardog.delete({
        dbName: 'cyio-config',
        sparqlQuery,
        queryId: 'Delete multiple Data Markings',
      });
    } catch (e) {
      console.log(e);
      throw e;
    }

    if (response === undefined || response.length === 0) throw new UserInputError(`Entity does not exist with ID ${id}`);
    return id;
  }
};

export const editDataMarkingById = async (dataMarkingId, input, dbName, dataSources, selectMap, schema) => {
  // make sure there is input data containing what is to be edited
  if (input === undefined || input.length === 0) throw new UserInputError(`No input data was supplied`);

  // WORKAROUND to remove immutable fields
  input = input.filter((element) => element.key !== 'id' && element.key !== 'created' && element.key !== 'modified');

  // check that the object to be edited exists with the predicates - only get the minimum of data
  const editSelect = ['id', 'created', 'modified'];
  for (const editItem of input) {
    editSelect.push(editItem.key);
  }

  const sparqlQuery = selectDataMarkingQuery(dataMarkingId, editSelect);
  const response = await dataSources.Stardog.queryById({
    dbName: 'cyio-config',
    sparqlQuery,
    queryId: 'Select Data Marking',
    singularizeSchema,
  });
  if (response.length === 0) throw new UserInputError(`Entity does not exist with ID ${dataMarkingId}`);

  // determine operation, if missing
  for (const editItem of input) {
    if (editItem.operation !== undefined) continue;

    // if value if empty then treat as a remove
    if (editItem.value.length === 0) {
      editItem.operation = 'remove';
      continue;
    }
    if (Array.isArray(editItem.value) && editItem.value[0] === null)
      throw new UserInputError(`Field "${editItem.key}" has invalid value "null"`);

    if (!response[0].hasOwnProperty(editItem.key)) {
      editItem.operation = 'add';
    } else {
      editItem.operation = 'replace';

      // Set operation to 'skip' if no change in value
      if (response[0][editItem.key] === editItem.value) editItem.operation = 'skip';
    }
  }

  // Push an edit to update the modified time of the object
  const timestamp = new Date().toISOString();
  if (!response[0].hasOwnProperty('created')) {
    const update = { key: 'created', value: [`${timestamp}`], operation: 'add' };
    input.push(update);
  }
  let operation = 'replace';
  if (!response[0].hasOwnProperty('modified')) operation = 'add';
  const update = { key: 'modified', value: [`${timestamp}`], operation: `${operation}` };
  input.push(update);

  // Handle the update to fields that have references to other object instances
  for (const editItem of input) {
    if (editItem.operation === 'skip') continue;

    let value;
    let fieldType;
    let objectType;
    let objArray;
    const iris = [];
    for (value of editItem.value) {
      switch (editItem.key) {
        case 'definition_type':
          if (!validateEnumValue(value, 'DataMarkingType', schema))
            throw new UserInputError(`Invalid value "${value}" for field "${editItem.key}".`);
          fieldType = 'simple';
          break;
        case 'tlp':
          if (!validateEnumValue(value, 'TLPLevel', schema))
            throw new UserInputError(`Invalid value "${value}" for field "${editItem.key}".`);
          editItem.value[0] = value.replace(/_/g, '+');
          fieldType = 'simple';
          break;
        case 'encrypt_in_transit':
          if (!validateEnumValue(value, 'EncryptInTransit', schema))
            throw new UserInputError(`Invalid value "${value}" for field "${editItem.key}".`);
          fieldType = 'simple';
          break;
        case 'permitted_actions':
          if (!validateEnumValue(value, 'PermittedActions', schema))
            throw new UserInputError(`Invalid value "${value}" for field "${editItem.key}".`);
          fieldType = 'simple';
          break;
        case 'affected_party_notifications':
          if (!validateEnumValue(value, 'AffectedPartyNotifications', schema))
            throw new UserInputError(`Invalid value "${value}" for field "${editItem.key}".`);
          fieldType = 'simple';
          break;
        case 'attribution':
          if (!validateEnumValue(value, 'ProviderAttribution', schema))
            throw new UserInputError(`Invalid value "${value}" for field "${editItem.key}".`);
          fieldType = 'simple';
          break;
        case 'unmodified_resale':
          if (!validateEnumValue(value, 'UnmodifiedResale', schema))
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

        const iri = `${objectMap[objectType].iriTemplate}-${value}`;
        const sparqlQuery = selectObjectIriByIdQuery(value, objectType);
        const result = await dataSources.Stardog.queryById({
          dbName: 'cyio-config',
          sparqlQuery,
          queryId: 'Obtaining IRI for the object with id',
          singularizeSchema,
        });
        if (result === undefined || result.length === 0) throw new UserInputError(`Entity does not exist with ID ${value}`);
        iris.push(`<${result[0].iri}>`);
      }
    }
    if (iris.length > 0) editItem.value = iris;
  }

  const query = updateQuery(
    `http://cyio.darklight.ai/marking-definition--${dataMarkingId}`,
    'http://docs.oasis-open.org/ns/cti/data-marking#MarkingDefinition',
    input,
    dataMarkingPredicateMap
  );
  if (query !== null) {
    let response;
    try {
      response = await dataSources.Stardog.edit({
        dbName: 'cyio-config',
        sparqlQuery: query,
        queryId: 'Update Data Marking',
      });
    } catch (e) {
      console.log(e);
      throw e;
    }

    if (response !== undefined && 'status' in response) {
      if (response.ok === false || response.status > 299) {
        // Handle reporting Stardog Error
        throw new UserInputError(response.statusText, {
          error_details: response.body.message ? response.body.message : response.body,
          error_code: response.body.code ? response.body.code : 'N/A',
        });
      }
    }
  }

  const select = selectDataMarkingQuery(dataMarkingId, selectMap.getNode('editDataMarking'));
  const result = await dataSources.Stardog.queryById({
    dbName: 'cyio-config',
    sparqlQuery: select,
    queryId: 'Select Data Marking',
    singularizeSchema,
  });
  const reducer = getReducer('DATA-MARKING');
  return reducer(result[0]);
};
