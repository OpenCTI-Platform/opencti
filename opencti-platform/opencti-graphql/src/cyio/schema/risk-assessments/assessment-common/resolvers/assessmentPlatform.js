import {riskSingularizeSchema as singularizeSchema } from '../../risk-mappings.js';
import {selectObjectIriByIdQuery} from '../../../global/global-utils.js';
import {compareValues, updateQuery, filterValues} from '../../../utils.js';
import {UserInputError} from "apollo-server-express";
import {
  selectExternalReferenceByIriQuery,
  selectNoteByIriQuery,
  selectLabelByIriQuery,
  getReducer as getGlobalReducer,
} from '../../../global/resolvers/sparql-query.js';
import {
  selectComponentByIriQuery,
  getReducer as getComponentReducer,
} from '../../component/resolvers/sparql-query.js';
import {
  getReducer, 
  selectAllAssessmentPlatforms,
  deleteAssessmentPlatformQuery,
  insertAssessmentPlatformQuery,
  selectAssessmentPlatformQuery,
  detachFromAssessmentPlatformQuery,
  assessmentPlatformPredicateMap,
} from './sparql-query.js';


const assessmentPlatformResolvers = {
	Query: {
    assessmentPlatforms: async (_, args, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectAllAssessmentPlatforms(selectMap.getNode("node"), args);
      let response;
      try {
        response = await dataSources.Stardog.queryAll({
          dbName,
          sparqlQuery,
          queryId: "Select Assessment Platform List",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const edges = [];
        const reducer = getReducer("ASSESSMENT-PLATFORM");
        let limit = (args.first === undefined ? response.length : args.first) ;
        let offset = (args.offset === undefined ? 0 : args.offset) ;
        let platformList ;
        if (args.orderedBy !== undefined ) {
          platformList = response.sort(compareValues(args.orderedBy, args.orderMode ));
        } else {
          platformList = response;
        }

        if (offset > platformList.length) return null;

        // for each Assessment Platform in the result set
        for (let platform of platformList) {
          // skip down past the offset
          if (offset) {
            offset--
            continue
          }

          if (platform.id === undefined || platform.id == null ) {
            console.log(`[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${platform.iri} missing field 'id'; skipping`);
            continue;
          }

          // filter out non-matching entries if a filter is to be applied
          if ('filters' in args && args.filters != null && args.filters.length > 0) {
            if (!filterValues(platform, args.filters, args.filterMode) ) {
              continue
            }
          }

          // if haven't reached limit to be returned
          if (limit) {
            let edge = {
              cursor: platform.iri,
              node: reducer(platform),
            }
            edges.push(edge)
            limit--;
          }
        }
        if (edges.length === 0 ) return null;
        return {
          pageInfo: {
            startCursor: edges[0].cursor,
            endCursor: edges[edges.length-1].cursor,
            hasNextPage: (args.first < platformList.length ? true : false),
            hasPreviousPage: (args.offset > 0 ? true : false),
            globalCount: platformList.length,
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
    assessmentPlatform: async (_, {id}, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectAssessmentPlatformQuery(id, selectMap.getNode("assessmentPlatform"));
      let response;
      try {
          response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: "Select Assessment Platform",
          singularizeSchema
          });
      } catch (e) {
          console.log(e)
          throw e
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
          const reducer = getReducer("ASSESSMENT-PLATFORM");
          return reducer(response[0]);  
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
	},
	Mutation: {
    createAssessmentPlatform: async ( _, {input}, {dbName, selectMap, dataSources} ) => {
			if (input.uses_components !== undefined && input.uses_components !== null) {
				// attempt to convert component's id to IRI
				let sparqlQuery, result;
				let componentIris = [];
				for (let componentId of input.uses_components) {
					sparqlQuery = selectObjectIriByIdQuery( componentId, 'component' );
					try {
						result = await dataSources.Stardog.queryById({
						dbName,
						sparqlQuery,
						queryId: "Select Component",
						singularizeSchema
						});
					} catch (e) {
							console.log(e)
							throw e
					}
					if (result === undefined || result.length === 0) throw new UserInputError(`Entity does not exist with ID ${componentId}`);
					componentIris.push(result[0].iri)
				}
				if (componentIris.length > 0) input.uses_components = componentIris;
			}

      // create the Assessment Platform
      const {id, query} = insertAssessmentPlatformQuery(input);
      try {
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: query,
          queryId: "Create Assessment Platform"
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      // retrieve information about the newly created Characterization to return to the user
      const select = selectAssessmentPlatformQuery(id, selectMap.getNode("createAssessmentPlatform"));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery: select,
          queryId: "Select Assessment Platform",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }
      const reducer = getReducer("ASSESSMENT-PLATFORM");
      return reducer(response[0]);
    },
    deleteAssessmentPlatform: async ( _, {id}, {dbName, dataSources} ) => {
      // check that the Assessment Platform exists
      const sparqlQuery = selectAssessmentPlatformQuery(id, null);
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: "Select Assessment Platform",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      if (response.length === 0) throw new UserInputError(`Entity does not exist with ID ${id}`);
      // work around issue where have an IRI but no body
      // if (response[0].id === undefined) throw new UserInputError(`Entity with ID ${id} is malformed`);
      let reducer = getReducer("ASSESSMENT-PLATFORM");
      const assessmentPlatform = (reducer(response[0]));
      
      // Detach any attached components
      if (assessmentPlatform.hasOwnProperty('uses_components_iri')) {
				for (let componentIri of assessmentPlatform.uses_components_iri) {
					const detachQuery = detachFromAssessmentPlatformQuery(id, 'uses_components', componentIri);
					try {
						await dataSources.Stardog.delete({
							dbName,
							sparqlQuery: detachQuery,
							queryId: "Detaching Component from Assessment Platform"
						});
					} catch (e) {
						console.log(e)
						throw e
					}    	
				}
      }

      // Delete the Assessment Platform itself
      const query = deleteAssessmentPlatformQuery(id);
      try {
        await dataSources.Stardog.delete({
          dbName,
          sparqlQuery: query,
          queryId: "Delete Assessment Platform"
        });
      } catch (e) {
        console.log(e)
        throw e
      }
      return id;
    },
    editAssessmentPlatform: async (_, {id, input}, {dbName, dataSources, selectMap}) => {
      // check that the Assessment Platform exists
      const sparqlQuery = selectAssessmentPlatformQuery(id, null);
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: "Select Assessment Platform",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      if (response.length === 0) throw new UserInputError(`Entity does not exist with ID ${id}`);
      const query = updateQuery(
        `http://csrc.nist.gov/ns/oscal/assessment/common#AssessmentPlatform-${id}`,
        "http://csrc.nist.gov/ns/oscal/assessment/common#AssessmentPlatform",
        input,
        assessmentPlatformPredicateMap
      )
      await dataSources.Stardog.edit({
        dbName,
        sparqlQuery: query,
        queryId: "Update Assessment Platform"
      });
      const select = selectAssessmentPlatformQuery(id, selectMap.getNode("editAssessmentPlatform"));
      const result = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery: select,
        queryId: "Select Assessment Platform",
        singularizeSchema
      });
      const reducer = getReducer("ASSESSMENT-PLATFORM");
      return reducer(result[0]);
    },
	},
	AssessmentPlatform :{
    labels: async (parent, _, {dbName, dataSources, }) => {
      if (parent.labels_iri === undefined) return [];
      let iriArray = parent.labels_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getGlobalReducer("LABEL");
        for (let iri of iriArray) {
          if (iri === undefined || !iri.includes('Label')) {
            continue;
          }
          const sparqlQuery = selectLabelByIriQuery(iri, null);
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
    links: async (parent, _, {dbName, dataSources, }) => {
      if (parent.ext_ref_iri === undefined) return [];
      let iriArray = parent.ext_ref_iri;
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
    remarks: async (parent, _, {dbName, dataSources, }) => {
      if (parent.notes_iri === undefined) return [];
      let iriArray = parent.notes_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getGlobalReducer("NOTE");
        for (let iri of iriArray) {
          if (iri === undefined || !iri.includes('Note')) {
            continue;
          }
          const sparqlQuery = selectNoteByIriQuery(iri, null);
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: "Select Remark",
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
		uses_components: async (parent, _, {dbName, dataSources, }) => {
      if (parent.uses_components_iri === undefined) return [];
      let iriArray = parent.uses_components_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getComponentReducer("COMPONENT");
        for (let iri of iriArray) {
          if (iri === undefined || !iri.includes('Component')) {
            continue;
          }
          const sparqlQuery = selectComponentByIriQuery(iri, null);
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: "Select Component",
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

export default assessmentPlatformResolvers;