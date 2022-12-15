import { UserInputError } from "apollo-server-express";
import { compareValues, filterValues, updateQuery, CyioError } from '../cyio/schema/utils.js';
import { selectObjectIriByIdQuery } from '../cyio/schema/global/global-utils.js';
import { 
  singularizeSchema, 
  getReducer,
  insertWorkspaceQuery,
  selectWorkspaceQuery,
  selectWorkspaceByIriQuery,
  selectAllWorkspacesQuery,
  deleteWorkspaceQuery,
  deleteWorkspaceByIriQuery,
  attachToWorkspaceQuery,
  detachFromWorkspaceQuery,
  workspacePredicateMap,
} from '../schema/sparql/cyio-workspace.js';

// import { SYSTEM_USER } from '../utils/access';


export const findById = async (user, workspaceId, dbName, dataSources, selectMap) => {
  const sparqlQuery = selectWorkspaceQuery(workspaceId, selectMap.getNode("workspace"));
  let response;
  try {
    response = await dataSources.Stardog.queryById({
      dbName,
      sparqlQuery,
      queryId: "Select Workspace",
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
    const reducer = getReducer("WORKSPACE");
    return reducer(response[0]);  
  }
};

export const findAll = async (user, args, dbName, dataSources, selectMap) => {
  const sparqlQuery = selectAllWorkspacesQuery(selectMap.getNode("node"), args);
  let response;
  try {
    response = await dataSources.Stardog.queryAll({
      dbName,
      sparqlQuery,
      queryId: "Select List of Workspaces",
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

  if (Array.isArray(response) && response.length < 1) return null;

  const edges = [];
  const reducer = getReducer("WORKSPACE");
  let filterCount, resultCount, limit, offset, limitSize, offsetSize;
  limitSize = limit = (args.first === undefined ? response.length : args.first) ;
  offsetSize = offset = (args.offset === undefined ? 0 : args.offset) ;
  filterCount = 0;

  let resultList ;
  if (args.orderedBy !== undefined ) {
    resultList = response.sort(compareValues(args.orderedBy, args.orderMode ));
  } else {
    resultList = response;
  }

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
  resultCount = resultList.length;
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

export const addWorkspace = async (user, input, dbName, dataSources, selectMap) => {
  // TODO: WORKAROUND to remove input fields with null or empty values so creation will work
  for (const [key, value] of Object.entries(input)) {
    if (Array.isArray(input[key]) && input[key].length === 0) {
      delete input[key];
      continue;
    }
    if (value === null || value.length === 0) {
      delete input[key];
    }
    if (key === 'type' ) {
      if (value !== 'dashboard' && value !== 'investigation') throw new CyioError(`Invalid workspace type value: ${value}`);
    }
  }
  // END WORKAROUND

  // set the owner to the id of the current user, else set it to be system
  let owner = (user ? user.id : '6a4b11e1-90ca-4e42-ba42-db7bc7f7d505' )
  input['owner'] = owner;

  // create the workspace
  const { iri, id, query } = insertWorkspaceQuery(input);
  await dataSources.Stardog.create({
    dbName,
    sparqlQuery: query,
    queryId: "Create Workspace"
  });

  // TODO: Attach to the parent (system-configuration/organization)
  // add the workspace to a parent object (if supplied)
  // const poamId = "22f2ad37-4f07-5182-bf4e-59ea197a73dc";
  // const attachQuery = attachToPOAMQuery(poamId, 'roles', iri );
  // try {
  //   await dataSources.Stardog.create({
  //     dbName,
  //     queryId: "Add Role to POAM",
  //     sparqlQuery: attachQuery
  //   });
  // } catch (e) {
  //   console.log(e)
  //   throw e
  // }
  // END WORKAROUND

  // retrieve information about the newly created Characterization to return to the user
  const select = selectWorkspaceQuery(id, selectMap.getNode("addWorkspace"));
  let response;
  try {
    response = await dataSources.Stardog.queryById({
      dbName,
      sparqlQuery: select,
      queryId: "Select Workspace",
      singularizeSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }
  const reducer = getReducer("WORKSPACE");
  return reducer(response[0]);
};

export const workspaceDelete = async (user, workspaceId, dbName, dataSources) => {
  // check that the Workspace exists
  const sparqlQuery = selectWorkspaceQuery(workspaceId, null);
  let response;
  try {
    response = await dataSources.Stardog.queryById({
      dbName,
      sparqlQuery,
      queryId: "Select Workspace",
      singularizeSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }

  if (response === undefined || response.length === 0) throw new CyioError(`Entity does not exist with ID ${id}`);
  let workspace = response[0];
  
  // Delete any EditUserContext that are attached.
  if ('editContext' in workspace) {
    for (let ctx in workspace.editContext) {
      let query = deleteEditUserContextByIriQuery(ctx);
      await dataSources.Sources.Stardog.delete({
        dbName,
        sparqlQuery: query,
        queryId: "Delete attached editUserContext"  
      });
    }
  }

  // TODO: Add support for objects when investigations are supported

  // detach the Workspace from the parent object (if supplied)
  // TODO: Detach from the parent (system-configuration/organization)
  // WORKAROUND detach the location to the default POAM until Metadata object is supported
  // const poamId = "22f2ad37-4f07-5182-bf4e-59ea197a73dc";
  // const detachQuery = detachFromPOAMQuery(poamId, 'locations', location.iri );
  // try {
  //   await dataSources.Stardog.create({
  //     dbName,
  //     queryId: "Detaching Risk from POAM",
  //     sparqlQuery: detachQuery
  //   });
  // } catch (e) {
  //   console.log(e)
  //   throw e
  // }
  // END WORKAROUND

  // Delete the Workspace itself
  const query = deleteWorkspaceQuery(workspaceId);
  try {
    let result = await dataSources.Stardog.delete({
      dbName,
      sparqlQuery: query,
      queryId: "Delete Workspace"
    });
  } catch (e) {
    console.log(e)
    throw e
  }
  return workspaceId;
};

export const workspaceEditField = async (user, workspaceId, input, dbName, dataSources, selectMap) => {
  // make sure there is input data containing what is to be edited
  if (input === undefined || input.length === 0) throw new CyioError(`No input data was supplied`);

  // TODO: WORKAROUND to remove immutable fields
  input = input.filter(element => (element.key !== 'id' && element.key !== 'created_at' && element.key !== 'updated_at'));

  // check that the object to be edited exists with the predicates - only get the minimum of data
  let editSelect = ['id','created_at','updated_at','type'];
  for (let editItem of input) {
    if (!editSelect.includes(editItem.key)) editSelect.push(editItem.key);
  }

  const sparqlQuery = selectWorkspaceQuery(workspaceId, editSelect );
  let response = await dataSources.Stardog.queryById({
    dbName,
    sparqlQuery,
    queryId: "Select Workspace",
    singularizeSchema
  })
  if (response.length === 0) throw new CyioError(`Entity does not exist with ID ${id}`);

  // determine operation, if missing
  for (let editItem of input) {
    if (editItem.operation !== undefined) continue;

    // if value if empty then treat as a remove
    if (editItem.value.length === 0 || editItem.value[0].length === 0) {
      editItem.operation = 'remove';
      continue;
    }
    if (!response[0].hasOwnProperty(editItem.key)) {
      editItem.operation = 'add';
    } else {
      editItem.operation = 'replace';
    }
  }

  // Push an edit to update the modified time of the object
  const timestamp = new Date().toISOString();
  if (!response[0].hasOwnProperty('created_at')) {
    let update = {key: "created_at", value:[`${timestamp}`], operation: "add"}
    input.push(update);
  }
  let operation = "replace";
  if (!response[0].hasOwnProperty('updated_at')) operation = "add";
  let update = {key: "updated_at", value:[`${timestamp}`], operation: `${operation}`}
  input.push(update);

  // obtain the IRIs for the referenced objects so that if one doesn't 
  // exists we have created anything yet.  For complex objects that are
  // private to this object, remove them (if needed) and add the new instances
  for (let editItem  of input) {
    let value, objType, objArray, iris=[], isId = true;
    let relationshipQuery;
    for (value of editItem.value) {
      switch(editItem.key) {
        default:
          isId = false;
          if (response[0].hasOwnProperty(editItem.key)) {
            if (response[0][editItem.key] === value) editItem.operation = 'skip';
          } else if (editItem.operation === 'remove') {
            editItem.operation = 'skip';
          }
          break;
      }

      if (isId && editItem.operation !== 'skip') {
        let query = selectObjectIriByIdQuery(value, objType);
        let result = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery: query,
          queryId: "Obtaining IRI for object by id",
          singularizeSchema
        });
        if (result === undefined || result.length === 0) throw new CyioError(`Entity does not exist with ID ${value}`);
        iris.push(`<${result[0].iri}>`);    
      }
    }

    // update value with array of IRIs
    if (iris.length > 0) editItem.value = iris;
  }

  const query = updateQuery(
    `http://cyio.darklight.ai/workspace--${workspaceId}`,
    `http://darklight.ai/ns/cyio/workspace#Workspace`,
    input,
    workspacePredicateMap
  );
  if (query !== null) {
    let response;
    try {
      response = await dataSources.Stardog.edit({
        dbName,
        sparqlQuery: query,
        queryId: "Update Workspace"
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

  //TODO: Need to test creation of an EditContext instance
  // if (user !== undefined && user !== null) {
  //   let propValues = {'name': user.user_email, 'focusOn': null};
  //   const { iri, id, query } = insertEditUserContextQuery(propValues);
  //   try {
  //     let result;
  //     result = await dataSources.Stardog.create({
  //         dbName,
  //         sparqlQuery: query,
  //         queryId: "Create EditUserContext"
  //     });
  //   } catch (e) {
  //     console.log(e)
  //     throw e
  //   }

  //   let sparqlQuery = attachToWorkspaceQuery(workspaceId, 'editContext', iri);
  //   try {
  //     let result;
  //     result = await dataSources.Stardog.create({
  //         dbName,
  //         sparqlQuery: sparqlQuery,
  //         queryId: "Attach EditContext to Workspace"
  //     });
  //   } catch (e) {
  //     console.log(e)
  //     throw e
  //   }
  // }

  // Retrieve the updated Workspace
  const select = selectWorkspaceQuery(workspaceId, selectMap.getNode("fieldPatch"));
  const result = await dataSources.Stardog.queryById({
    dbName,
    sparqlQuery: select,
    queryId: "Select Workspace",
    singularizeSchema
  });

  let reducer = getReducer("WORKSPACE");
  return reducer(result[0]);
};

// support for investigations
export const workspaceAddRelation = async (user, workspaceId, input) => {};
export const workspaceAddRelations = async (user, workspaceId, input) => {};
export const workspaceDeleteRelation = async (user, workspaceId, toId, relationshipType) => {};
export const workspaceDeleteRelations = async (user, workspaceId, toIds, relationshipType) => {};
export const objects = async (user, workspaceId, args, dbName, dataSources, selectMap) => { return [] };

// subscriptions
export const fetchEditContext = async (workspaceId) => { return [] };
export const workspaceCleanContext = async (user, workspaceId, dbName, dataSources, selectMap) => { return null };
export const workspaceEditContext = async (user, workspaceId, input, dbName, dataSources, selectMap) => { return null };

// utility
export const findUserById = async (user, workspaceOwner, dbName, dataSources, selectMap) => { 
  // TODO: Implement retrieval of User from Keycloak
  if ((workspaceOwner === undefined || workspaceOwner === null) || workspaceOwner === '6a4b11e1-90ca-4e42-ba42-db7bc7f7d505') {
  // return SYSTEM_USER;
  // WORKAROUND - defined SYSTEM_USER inline
  return {
      id: '6a4b11e1-90ca-4e42-ba42-db7bc7f7d505',
      internal_id: '6a4b11e1-90ca-4e42-ba42-db7bc7f7d505',
      name: "SYSTEM",
      user_email: 'SYSTEM',
      origin: {},
      roles: [{ name: 'Administrator' }],
      capabilities: [{ name: 'BYPASS' }],
      allowed_marking: [],
      }
  // END WORKAROUND
  }
};
