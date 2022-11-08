import { riskSingularizeSchema as singularizeSchema } from '../../risk-mappings.js';
import {compareValues, updateQuery, filterValues, CyioError} from '../../../utils.js';
import {convertToProperties} from '../../riskUtils.js'
import {selectObjectIriByIdQuery} from '../../../global/global-utils.js';
import {UserInputError} from "apollo-server-express";
import {
  selectLabelByIriQuery,
  selectExternalReferenceByIriQuery,
  selectNoteByIriQuery,
  getReducer as getGlobalReducer,
} from '../../../global/resolvers/sparql-query.js';
import {
  getReducer, 
  insertRiskResponseQuery,
  selectRiskResponseQuery,
  selectAllRiskResponses,
  deleteRiskResponseQuery,
  attachToRiskResponseQuery,
  selectOscalTaskByIriQuery,
  selectRequiredAssetByIriQuery,
  insertActorQuery,
  insertActorsQuery,
  selectActorQuery,
  selectActorByIriQuery,
  attachToOriginQuery,
  insertOriginQuery,
  deleteOriginByIriQuery,
  selectOriginQuery,
  selectAllOrigins,
  selectOriginByIriQuery,
  attachToRiskQuery,
  detachFromRiskQuery,
  selectRiskQuery,
  riskResponsePredicateMap,
  detachFromRiskResponseQuery,
} from './sparql-query.js';


const riskResponseResolvers = {
  Query: {
    riskResponses: async (_, args, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectAllRiskResponses(selectMap.getNode("node"), args);
      let response;
      try {
        response = await dataSources.Stardog.queryAll({
          dbName,
          sparqlQuery,
          queryId: "Select Risk Response List",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const edges = [];
        const reducer = getReducer("RISK-RESPONSE");
        let filterCount, resultCount, limit, offset, limitSize, offsetSize;
        limitSize = limit = (args.first === undefined ? response.length : args.first) ;
        offsetSize = offset = (args.offset === undefined ? 0 : args.offset) ;
        filterCount = 0;
        let riskResponseList ;
        if (args.orderedBy !== undefined ) {
          riskResponseList = response.sort(compareValues(args.orderedBy, args.orderMode ));
        } else {
          riskResponseList = response;
        }

        if (offset > riskResponseList.length) return null;

        // for each Risk Response in the result set
        for (let riskResponse of riskResponseList) {
          // skip down past the offset
          if (offset) {
            offset--
            continue
          }

          if (riskResponse.id === undefined || riskResponse.id == null ) {
            console.log(`[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${riskResponse.iri} missing field 'id'; skipping`);
            continue;
          }

          // if props were requested
          if (selectMap.getNode('node').includes('props')) {
            let props = convertToProperties(riskResponse, riskResponsePredicateMap);
            if (props !== null) riskResponse.props = props;
          }

          // filter out non-matching entries if a filter is to be applied
          if ('filters' in args && args.filters != null && args.filters.length > 0) {
            if (!filterValues(riskResponse, args.filters, args.filterMode) ) {
              continue
            }
            filterCount++;
          }

          // if haven't reached limit to be returned
          if (limit) {
            let edge = {
              cursor: riskResponse.iri,
              node: reducer(riskResponse),
            }
            edges.push(edge)
            limit--;
            if (limit === 0) break;
          }
        }
        // check if there is data to be returned
        if (edges.length === 0 ) return null;
        let hasNextPage = false, hasPreviousPage = false;
        resultCount = riskResponseList.length;
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
      } else {
        // Handle reporting Stardog Error
        if (typeof (response) === 'object' && 'body' in response) {
          throw new UserInputError(response.statusText, {
            error_details: (response.body.message ? response.body.message : response.body),
            error_code: (response.body.code ? response.body.code : 'N/A')
          });
        } else {
          return null;
        }
      }
    },
    riskResponse: async (_, {id}, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectRiskResponseQuery(id, selectMap.getNode("riskResponse"));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: "Select Risk Response",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        let riskResponse = response[0];

        // if props were requested
        if (selectMap.getNode('riskResponse').includes('props')) {
          let props = convertToProperties(riskResponse, riskResponsePredicateMap);
          if (props !== null) riskResponse.props = props;
        }

        const reducer = getReducer("RISK-RESPONSE");
        return reducer(riskResponse);  
      } else {
        // Handle reporting Stardog Error
        if (typeof (response) === 'object' && 'body' in response) {
          throw new UserInputError(response.statusText, {
            error_details: (response.body.message ? response.body.message : response.body),
            error_code: (response.body.code ? response.body.code : 'N/A')
          });
        } else {
          return null;
        }
      }
    }
  },
  Mutation: {
    createRiskResponse: async ( _, {input}, {dbName, selectMap, dataSources} ) => {
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

      // Setup to handle embedded objects to be created
      let origins, assetIris = [], taskIris = [], relatedTasks = [], riskId;

      // check to see if risk exists
      if (input.risk_id !== undefined) {
        // check that the risk exists
        const sparqlQuery = selectRiskQuery(input.risk_id, ['id']);
        let response;
        try {
          response = await dataSources.Stardog.queryById({
            dbName,
            sparqlQuery,
            queryId: "Select Risk",
            singularizeSchema
          });
        } catch (e) {
          console.log(e)
          throw e
        }
        if (response.length === 0) throw new CyioError(`Risk does not exist with ID ${id}`);
        riskId = input.risk_id;
      }
      if (input.origins !== undefined) {
        if (input.origins.length === 0) throw new CyioError(`No origin of the Risk Response provided.`)
        origins = input.origins;
      }
      if (input.required_assets !== undefined) {
        for (let assetId of input.required_assets) {
          let sparqlQuery, result;
          sparqlQuery = selectObjectIriByIdQuery( assetId, 'required-asset');
          try {
            result = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: "Select Object",
              singularizeSchema
            });
          } catch (e) {
            console.log(e)
            throw e
          }
  
          if (result == undefined || result.length === 0) throw new CyioError(`Entity does not exist with ID ${assetId}`);
          assetIris.push(`<${result[0].iri}>`);
        }
      }
      if (input.tasks !== undefined) {
        for (let taskId of input.tasks) {
          let sparqlQuery, result;
          sparqlQuery = selectObjectIriByIdQuery( taskId, 'oscal-task');
          try {
            result = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: "Select Object",
              singularizeSchema
            });
          } catch (e) {
            console.log(e)
            throw e
          }
  
          if (result == undefined || result.length === 0) throw new CyioError(`Entity does not exist with ID ${taskId}`);
          taskIris.push(`<${result[0].iri}>`);
        }
      }

      // generate query to create the Risk Response
      const {iri, id, query} = insertRiskResponseQuery(input);

      // TODO: AB#5864 - Check if the RiskResponse already exists

      // create the actual risk response
      try {
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: query,
          queryId: "Create Risk Response"
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      // create any origins supplied and attach them to the Risk Response
      if (origins !== undefined && origins !== null ) {
        let originIris = [];
        for (let origin of origins) {
          let actors = origin.origin_actors;
          let relatedTasks = origin.related_tasks;

          // create the origin
          const {iri, id, query} = insertOriginQuery(origin);
          try {
            await dataSources.Stardog.create({
              dbName,
              sparqlQuery: query,
              queryId: "Create Origin"
            });
          } catch (e) {
            console.log(e)
            throw e
          }

          // create any Actors supplied and attach them to the Origin
          if (actors !== undefined && actors !== null ) {
            let sparqlQuery, result;
            for (let actor of actors) {
              // check to see if the referenced actor exists and get its IRI
              sparqlQuery = selectObjectIriByIdQuery( actor.actor_ref, actor.actor_type);
              try {
                result = await dataSources.Stardog.queryById({
                  dbName,
                  sparqlQuery,
                  queryId: "Select Object",
                  singularizeSchema
                });
              } catch (e) {
                console.log(e)
                throw e
              }
              if (result == undefined || result.length === 0) throw new CyioError(`Entity does not exist with ID ${actor.actor_ref}`);
              actor.actor_ref = result[0].iri;
              // if a role reference was provided
              if (actor.role_ref !== undefined) {
                // check if the role reference exists and get its IRI
                sparqlQuery = selectObjectIriByIdQuery( actor.role_ref, 'role');
                try {
                  result = await dataSources.Stardog.queryById({
                    dbName,
                    sparqlQuery,
                    queryId: "Select Object",
                    singularizeSchema
                  });
                } catch (e) {
                  console.log(e)
                  throw e
                }
                if (result == undefined || result.length === 0) throw new CyioError(`Entity does not exist with ID ${actor.role_ref}`);
                actor.role_ref = result[0].iri;
              }
            }
            // create the Actors
            const { actorIris, query } = insertActorsQuery( actors );
            try {
              await dataSources.Stardog.create({
                dbName,
                sparqlQuery: query,
                queryId: "Create Actors of Origin"
              });
            } catch (e) {
              console.log(e)
              throw e
            }

            // attach Actor(s) to the Origin
            const actorAttachQuery = attachToOriginQuery(id, 'origin_actors', actorIris );
            try {
              await dataSources.Stardog.create({
                dbName,
                queryId: "Add Actor to Origin",
                sparqlQuery: actorAttachQuery
              });
            } catch (e) {
              console.log(e)
              throw e
            }
          }

          // TODO: create and attach task references; these are different than OscalTasks
          if (relatedTasks !== undefined && relatedTasks != null) {
            // attach related tasks to the Origin
            const actorAttachQuery = attachToOriginQuery(id, 'related_tasks', relatedTaskIris );
            try {
              await dataSources.Stardog.create({
                dbName,
                queryId: "Add related task(s) to Origin",
                sparqlQuery: actorAttachQuery
              });
            } catch (e) {
              console.log(e)
              throw e
            }
          }
          originIris.push(iri);
        }

        if (originIris.length > 0) {
          // attach the origin(s) to the Risk Response
          const originAttachQuery = attachToRiskResponseQuery(id, 'origins', originIris );
          try {
            await dataSources.Stardog.create({
              dbName,
              queryId: "Add Asset to Risk Response",
              sparqlQuery: originAttachQuery
            });
          } catch (e) {
            console.log(e)
            throw e
          }
        }
      }

      // attach any related assets referenced to the Risk Response
      if (assetIris !== undefined && assetIris.length > 0) {
        // attach task to the Risk Response
        const assetAttachQuery = attachToRiskResponseQuery(id, 'related_assets', assetIris );
        try {
          await dataSources.Stardog.create({
            dbName,
            queryId: "Add Asset to Risk Response",
            sparqlQuery: assetAttachQuery
          });
        } catch (e) {
          console.log(e)
          throw e
        }
      }
      // create any task supplied and attach them to the Risk Response
      if (taskIris !== undefined && taskIris.length > 0) {
        // attach task to the Risk Response
        const taskAttachQuery = attachToRiskResponseQuery(id, 'tasks', taskIris );
        try {
          await dataSources.Stardog.create({
            dbName,
            queryId: "Add Task to Risk Response",
            sparqlQuery: taskAttachQuery
          });
        } catch (e) {
          console.log(e)
          throw e
        }
      }
      // attach the Risk Response to the Risk
      if (riskId !== undefined && riskId !== null) {
        const attachQuery = attachToRiskQuery( riskId, 'remediations', iri );
        try {
          await dataSources.Stardog.create({
            dbName,
            sparqlQuery: attachQuery,
            queryId: "Add Remediation to Risk"
          });
        } catch (e) {
          console.log(e)
          throw e
        } 
      }

      // retrieve information about the newly created Characterization to return to the user
      const select = selectRiskResponseQuery(id, selectMap.getNode("createRiskResponse"));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery: select,
          queryId: "Select Risk Response",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }
      const reducer = getReducer("RISK-RESPONSE");
      return reducer(response[0]);
    },
    deleteRiskResponse: async ( _, {riskId, id}, {dbName, dataSources} ) => {
      // check that the risk response exists
      const sparqlQuery = selectRiskResponseQuery(id, null);
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: "Select Risk Response",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      if (response.length === 0) throw new CyioError(`Entity does not exist with ID ${id}`);
      let reducer = getReducer("RISK-RESPONSE");
      const riskResponse = (reducer(response[0]));
      
      // detach the Risk Response from the Risk
      if (riskId !== undefined && riskId !== null) {
        const iri = `http://csrc.nist.gov/ns/oscal/assessment/common#RiskResponse-${id}`
        const detachQuery = detachFromRiskQuery( riskId, 'remediations', iri );
        try {
          await dataSources.Stardog.delete({
            dbName,
            sparqlQuery: detachQuery,
            queryId: "Detach Risk Response from Risk"
          });
        } catch (e) {
          console.log(e)
          throw e
        }
      }
      
      // Delete any attached origins
      if (riskResponse.hasOwnProperty('origins_iri')) {
        for (const originIri of riskResponse.origins_iri) {
          const originQuery = deleteOriginByIriQuery(originIri);
          try {
            await dataSources.Stardog.delete({
              dbName,
              sparqlQuery: originQuery,
              queryId: "Delete Origin from Risk Response"
            });
          } catch (e) {
            console.log(e)
            throw e
          }    
        }
      }

      // Delete the characterization itself
      const query = deleteRiskResponseQuery(id);
      try {
        await dataSources.Stardog.delete({
          dbName,
          sparqlQuery: query,
          queryId: "Delete Risk Response"
        });
      } catch (e) {
        console.log(e)
        throw e
      }
      return id;
    },
    editRiskResponse: async (_, {id, input}, {dbName, dataSources, selectMap}) => {
      // make sure there is input data containing what is to be edited
      if (input === undefined || input.length === 0) throw new CyioError(`No input data was supplied`);

      // TODO: WORKAROUND to remove immutable fields
      input = input.filter(element => (element.key !== 'id' && element.key !== 'created' && element.key !== 'modified'));
      
      // check that the object to be edited exists with minimal predicates
      let editSelect = ['id','created','modified'];
      for (let editItem of input) {
        editSelect.push(editItem.key);
      }
      const sparqlQuery = selectRiskResponseQuery(id, editSelect );
      let response = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery,
        queryId: "Select Risk Response",
        singularizeSchema
      });
      if (response.length === 0) throw new CyioError(`Entity does not exist with ID ${id}`);

      // determine operation, if not specified
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
      if (!response[0].hasOwnProperty('created')) {
        let update = {key: "created", value:[`${timestamp}`], operation: "add"}
        input.push(update);
      }
      let operation = "replace";
      if (!response[0].hasOwnProperty('modified')) operation = "add";
      let update = {key: "modified", value:[`${timestamp}`], operation: `${operation}`}
      input.push(update);

      // obtain the IRIs for the referenced objects so that if one doesn't 
      // exists we have created anything yet.  For complex objects that are
      // private to this object, remove them (if needed) and add the new instances
      for (let editItem  of input) {
        let value, objType, objArray, iris=[], isId = true;
        let relationshipQuery, queryDetails;
        for (value of editItem.value) {
          switch(editItem.key) {
            case 'origins':
              isId = false;
              objArray = JSON.parse(value);

              for (let origin of objArray) {
                let {iri: originIri, id: originId, query: originQuery} = insertOriginQuery(origin);
                if (response[0].hasOwnProperty('origins')) {
                  for (let currentOrigin of response[0].origins) {
                    // check if origin is being changed
                    if (originIri === `<${currentOrigin}>`) {
                        editItem.operation = 'skip';
                        break;
                    }
                  }  
                }
                if (editItem.operation === 'skip') break;
              }

              if (editItem.operation === 'skip') break;
              if (editItem.operation !== 'add') {
                if (response[0].hasOwnProperty('origins')) {
                  // find the existing origin of the RiskResponse
                  for (const origin of response[0].origins) {
                    if (origin.includes('Origin')) {
                      let originQuery;

                      // detach the Origin object from the Risk Response
                      originQuery = detachFromRiskResponseQuery(id, 'origins', origin);
                      await dataSources.Stardog.delete({
                        dbName,
                        sparqlQuery: originQuery,
                        queryId: "Detach Origin from RiskResponse"
                      });
                    }
                  }
                }
              }

              if (editItem.operation !== 'delete') {
                for (let origin of objArray) {
                  let results;
  
                  // check if requested origin already exists
                  let {iri: originIri, id: originId, query: originQuery} = insertOriginQuery(origin);
                  let sparqlQuery = selectOriginQuery(originId, ['id','origin_actors']);
                  try {
                    results = await dataSources.Stardog.queryById({
                        dbName,
                        sparqlQuery,
                        queryId: "Select Origin",
                        singularizeSchema
                        });
                  } catch (e) {
                      console.log(e)
                      throw e
                  }
        
                  if (results === undefined || results.length === 0) {
                    // create the new Origin object
                    await dataSources.Stardog.create({
                      dbName,
                      sparqlQuery: originQuery,
                      queryId: "Create Origin for RiskResponse"
                    });
                  }

                  if (results === undefined || results.length === 0 || !results[0].hasOwnProperty('origin_actors')) {
                    // Find the iri for each actor
                    let actorIris = [];
                    for (let actor of origin.origin_actors) {
                      if (actor.actor_type.includes('_')) actor.actor_type = actor.actor_type.replace(/_/g, '-');
                      let sparqlQuery, result;
                      // determine what IRI of the actor_ref 
                      sparqlQuery = selectObjectIriByIdQuery( actor.actor_ref, actor.actor_type);
                      try {
                        result = await dataSources.Stardog.queryById({
                            dbName,
                            sparqlQuery,
                            queryId: "Select Object",
                            singularizeSchema
                            });
                      } catch (e) {
                          console.log(e)
                          throw e
                      }
                      if (result == undefined || result.length === 0) throw new CyioError(`Entity does not exist with ID ${actor.actor_ref}`); 
                      actor.actor_ref = (result[0].iri.includes('<') ? `${result[0].iri}` : `<${result[0].iri}>`);

                      // attempt to find the actor
                      let {iri: actorIri, id: actorId, query} = insertActorQuery(actor);
                      sparqlQuery = selectActorByIriQuery(actorIri, ['id','actor_type','actor_ref'])
                      try {
                        result = await dataSources.Stardog.queryById({
                            dbName,
                            sparqlQuery,
                            queryId: "Select Actor",
                            singularizeSchema
                            });
                      } catch (e) {
                          console.log(e)
                          throw e
                      }
                      if (result === undefined || result.length === 0) {
                        // need to create the actor
                        try {
                          await dataSources.Stardog.create({
                            dbName,
                            sparqlQuery: query,
                            queryId: "Create Actor of Origin"
                          });
                        } catch (e) {
                          console.log(e)
                          throw e
                        }
                      }
                      actorIris.push((actorIri.includes('<') ? `${actorIri}` : `<${actorIri}>`));
                    }
    
                    // attach the actor(s) to the Origin
                    let sparqlQuery = attachToOriginQuery(originId, 'origin_actors', actorIris);
                    try {
                      await dataSources.Stardog.create({
                        dbName,
                        queryId: "Add Actor to Origin",
                        sparqlQuery: sparqlQuery
                      });
                    } catch (e) {
                      console.log(e)
                      throw e
                    }
                  }

                  // attach the new Origin object(s) to the RiskResponse
                  relationshipQuery = attachToRiskResponseQuery(id, 'origins', originIri);
                  await dataSources.Stardog.create({
                    dbName,
                    sparqlQuery: relationshipQuery,
                    queryId: "Add Origins to RiskResponse"
                  });
                }
              }

              editItem.operation = 'skip';
              break;
            default:
              isId = false;
              break;
            }
  
            if (isId) {
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
          if (iris.length > 0) editItem.value = iris;
        }
        
      const query = updateQuery(
        `http://csrc.nist.gov/ns/oscal/assessment/common#RiskResponse-${id}`,
        "http://csrc.nist.gov/ns/oscal/assessment/common#RiskResponse",
        input,
        riskResponsePredicateMap
      );
      if (query !== null ) {
        response = await dataSources.Stardog.edit({
          dbName,
          sparqlQuery: query,
          queryId: "Update Risk Response"
        });
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

      const select = selectRiskResponseQuery(id, selectMap.getNode("editRiskResponse"));
      let result;
      try {
        result = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery: select,
          queryId: "Select Risk Response",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      const reducer = getReducer("RISK-RESPONSE");
      return reducer(result[0]);
    },
  },
  // field-level resolvers
  RiskResponse: {
    labels: async (parent, _, {dbName, dataSources, selectMap}) => {
      if (parent.labels_iri === undefined) return [];
      let iriArray = parent.labels_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getGlobalReducer("LABEL");
        for (let iri of iriArray) {
          if (iri === undefined || !iri.includes('Label')) {
            continue;
          }
          const sparqlQuery = selectLabelByIriQuery(iri, selectMap.getNode("labels"));
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: "Select Label",
              singularizeSchema
            });
          } catch (e) {
            console.log(e)
            throw e
          }
          if (response === undefined) return [];
          if (Array.isArray(response) && response.length > 0) {
            results.push(reducer(response[0]))
          }
          else {
            // Handle reporting Stardog Error
            if (typeof (response) === 'object' && 'body' in response) {
              throw new UserInputError(response.statusText, {
                error_details: (response.body.message ? response.body.message : response.body),
                error_code: (response.body.code ? response.body.code : 'N/A')
              });
            }
          }  
        }
        return results;
      } else {
        return [];
      }
    },
    links: async (parent, _, {dbName, dataSources, selectMap}) => {
      if (parent.links_iri === undefined) return [];
      let iriArray = parent.links_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getGlobalReducer("EXTERNAL-REFERENCE");
        for (let iri of iriArray) {
          if (iri === undefined || !iri.includes('ExternalReference')) {
            continue;
          }
          const sparqlQuery = selectExternalReferenceByIriQuery(iri, selectMap.getNode("links"));
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: "Select Link",
              singularizeSchema
            });
          } catch (e) {
            console.log(e)
            throw e
          }
          if (response === undefined) return [];
          if (Array.isArray(response) && response.length > 0) {
            results.push(reducer(response[0]))
          }
          else {
            // Handle reporting Stardog Error
            if (typeof (response) === 'object' && 'body' in response) {
              throw new UserInputError(response.statusText, {
                error_details: (response.body.message ? response.body.message : response.body),
                error_code: (response.body.code ? response.body.code : 'N/A')
              });
            }
          }  
        }
        return results;
      } else {
        return [];
      }
    },
    remarks: async (parent, _, {dbName, dataSources, selectMap}) => {
      if (parent.remarks_iri === undefined) return [];
      let iriArray = parent.remarks_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getGlobalReducer("NOTE");
        for (let iri of iriArray) {
          if (iri === undefined || !iri.includes('Note')) {
            continue;
          }
          const sparqlQuery = selectNoteByIriQuery(iri, selectMap.getNode("remarks"));
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: "Select Note",
              singularizeSchema
            });
          } catch (e) {
            console.log(e)
            throw e
          }
          if (response === undefined) return [];
          if (Array.isArray(response) && response.length > 0) {
            results.push(reducer(response[0]))
          }
          else {
            // Handle reporting Stardog Error
            if (typeof (response) === 'object' && 'body' in response) {
              throw new UserInputError(response.statusText, {
                error_details: (response.body.message ? response.body.message : response.body),
                error_code: (response.body.code ? response.body.code : 'N/A')
              });
            }
          }  
        }
        return results;
      } else {
        return [];
      }
    },
    origins:async (parent, _, {dbName, dataSources, selectMap}) => {
      if (parent.origins_iri === undefined) return [];
      const results = [];
      const reducer = getReducer("ORIGIN");
      let sparqlQuery = selectAllOrigins(selectMap.getNode('origins'), undefined, parent);
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: "Select Referenced Origins",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }
      if (response === undefined || response.length === 0) return null;

      // Handle reporting Stardog Error
      if (typeof (response) === 'object' && 'body' in response) {
        throw new UserInputError(response.statusText, {
          error_details: (response.body.message ? response.body.message : response.body),
          error_code: (response.body.code ? response.body.code : 'N/A')
        });
      }

      for (let origin of response) {
        results.push(reducer(origin));
      }

      // check if there is data to be returned
      if (results.length === 0 ) return [];
      return results;
    },
    required_assets: async (parent, _, {dbName, dataSources, selectMap}) => {
      if (parent.required_assets_iri === undefined) return [];
      let iriArray = parent.required_assets_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getReducer("REQUIRED-ASSET");
        for (let iri of iriArray) {
          if (iri === undefined || !iri.includes('RequiredAsset')) {
            continue;
          }
          const sparqlQuery = selectRequiredAssetByIriQuery(iri, selectMap.getNode("required_assets"));
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: "Select Required Asset",
              singularizeSchema
            });
          } catch (e) {
            console.log(e)
            throw e
          }
          if (response === undefined) return [];
          if (Array.isArray(response) && response.length > 0) {
            results.push(reducer(response[0]))
          }
          else {
            // Handle reporting Stardog Error
            if (typeof (response) === 'object' && 'body' in response) {
              throw new UserInputError(response.statusText, {
                error_details: (response.body.message ? response.body.message : response.body),
                error_code: (response.body.code ? response.body.code : 'N/A')
              });
            }
          }  
        }
        return results;
      } else {
        return [];
      }
    },
    tasks: async (parent, _, {dbName, dataSources, selectMap}) => {
      if (parent.tasks_iri === undefined) return [];
      let iriArray = parent.tasks_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getReducer("TASK");
        for (let iri of iriArray) {
          if (iri === undefined || !iri.includes('Task')) {
            continue;
          }
          const sparqlQuery = selectOscalTaskByIriQuery(iri, selectMap.getNode("tasks"));
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: "Select Task",
              singularizeSchema
            });
          } catch (e) {
            console.log(e)
            throw e
          }
          if (response === undefined) return [];
          if (Array.isArray(response) && response.length > 0) {
            results.push(reducer(response[0]))
          }
          else {
            // Handle reporting Stardog Error
            if (typeof (response) === 'object' && 'body' in response) {
              throw new UserInputError(response.statusText, {
                error_details: (response.body.message ? response.body.message : response.body),
                error_code: (response.body.code ? response.body.code : 'N/A')
              });
            }
          }  
        }
        return results;
      } else {
        return [];
      }
    },  
  }
}

export default riskResponseResolvers;
