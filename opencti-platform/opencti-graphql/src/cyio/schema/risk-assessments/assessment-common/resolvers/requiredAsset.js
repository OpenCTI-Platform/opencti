import { riskSingularizeSchema as singularizeSchema } from '../../risk-mappings.js';
import {compareValues, updateQuery, filterValues} from '../../../utils.js';
import {UserInputError} from "apollo-server-express";
import {
  selectLabelByIriQuery,
  selectExternalReferenceByIriQuery,
  selectNoteByIriQuery,
  getReducer as getGlobalReducer,
} from '../../../global/resolvers/sparql-query.js';
import {
  getReducer, 
  insertRequiredAssetQuery,
  selectRequiredAssetQuery,
  selectAllRequiredAssets,
  deleteRequiredAssetQuery,
  attachToRequiredAssetQuery,
  attachToRiskResponseQuery,
  detachFromRiskResponseQuery,
  insertSubjectsQuery,
  selectSubjectByIriQuery,
  deleteSubjectByIriQuery,
  requiredAssetPredicateMap,
} from './sparql-query.js';
import { selectObjectIriByIdQuery } from '../../../global/global-utils.js';


const requiredAssetResolvers = {
  Query: {
    requiredAssets: async (_, args, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectAllRequiredAssets(selectMap.getNode("node"), args);
      let response;
      try {
        response = await dataSources.Stardog.queryAll({
          dbName,
          sparqlQuery,
          queryId: "Select Required Asset List",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const edges = [];
        const reducer = getReducer("REQUIRED-ASSET");
        let filterCount, resultCount, limit, offset, limitSize, offsetSize;
        limitSize = limit = (args.first === undefined ? response.length : args.first) ;
        offsetSize = offset = (args.offset === undefined ? 0 : args.offset) ;
        filterCount = 0;
        let reqAssetList ;
        if (args.orderedBy !== undefined ) {
          reqAssetList = response.sort(compareValues(args.orderedBy, args.orderMode ));
        } else {
          reqAssetList = response;
        }

        if (offset > reqAssetList.length) return null;

        // for each Required Asset in the result set
        for (let reqAsset of reqAssetList) {
          // skip down past the offset
          if (offset) {
            offset--
            continue
          }

          if (reqAsset.id === undefined || reqAsset.id == null ) {
            console.log(`[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${reqAsset.iri} missing field 'id'; skipping`);
            continue;
          }

          // filter out non-matching entries if a filter is to be applied
          if ('filters' in args && args.filters != null && args.filters.length > 0) {
            if (!filterValues(reqAsset, args.filters, args.filterMode) ) {
              continue
            }
            filterCount++;
          }

          // if haven't reached limit to be returned
          if (limit) {
            let edge = {
              cursor: reqAsset.iri,
              node: reducer(reqAsset),
            }
            edges.push(edge)
            limit--;
          }
        }
        // check if there is data to be returned
        if (edges.length === 0 ) return null;
        let hasNextPage = false, hasPreviousPage = false;
        resultCount = reqAssetList.length;
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
    requiredAsset: async (_, {id}, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectRequiredAssetQuery(id, selectMap.getNode("requiredAsset"));
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

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
          const reducer = getReducer("REQUIRED-ASSET");
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
    createRequiredAsset: async ( _, {input}, {dbName, selectMap, dataSources} ) => {
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
      let subjects, remediationId, links = [], remarks = [];
      if (input.remediation_id !== undefined) remediationId = input.remediation_id
      if (input.subjects !== undefined) subjects = input.subjects;

      // obtain the IRIs for the referenced objects so that if one doesn't exists we have created anything yet.
      if (input.links !== undefined && input.links !== null) {
        for (let linkId of input.links) {
          let sparqlQuery = selectObjectIriByIdQuery( linkId, 'link');
          let result = await dataSources.Stardog.queryById({
            dbName,
            sparqlQuery,
            queryId: "Obtaining IRI for Link object with id",
            singularizeSchema
          });
          if (result === undefined || result.length === 0) throw new UserInputError(`Link object does not exist with ID ${taskId}`);
          links.push(`<${result[0].iri}>`);
        }
        delete input.links;
      }
      if (input.remarks !== undefined && input.remarks !== null) {
        for (let remarkId of input.remarks) {
          let sparqlQuery = selectObjectIriByIdQuery( remarkId, 'remark');
          let result = await dataSources.Stardog.queryById({
            dbName,
            sparqlQuery,
            queryId: "Obtaining IRI for Remark object with id",
            singularizeSchema
          });
          if (result === undefined || result.length === 0) throw new UserInputError(`Remark object does not exist with ID ${taskId}`);
          remarks.push(`<${result[0].iri}>`);
        }
        delete input.remarks;
      }

      // check that the Subject exits
      let sparqlQuery, result;
      if (subjects !== undefined && subjects !==  null) {
        for (let subject of subjects) {
          sparqlQuery = selectObjectIriByIdQuery(subject.subject_ref, subject.subject_type);
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
  
          if (result == undefined || result.length === 0) throw new UserInputError(`Entity does not exist with ID ${subject.subject_ref}`);
          subject.subject_ref = result[0].iri;
        }
      }

      // create the Required Asset
      const {iri, id, query} = insertRequiredAssetQuery(input);
      try {
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: query,
          queryId: "Create Required Asset"
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      // add the Required Asset to the Risk Response
      if (remediationId !== undefined && remediationId !== null) {
        const attachQuery = attachToRiskResponseQuery( remediationId, 'required_assets', iri );
        try {
          await dataSources.Stardog.create({
            dbName,
            sparqlQuery: attachQuery,
            queryId: "Add Required Asset to Remediation"
          });
        } catch (e) {
          console.log(e)
          throw e
        }  
      }

      // create any subjects supplied and attach them to the Required Asset
      if (subjects !== undefined && subjects !== null ) {
        // create the Subject
        const { subjectIris, query } = insertSubjectsQuery( subjects );
        try {
          await dataSources.Stardog.create({
            dbName,
            sparqlQuery: query,
            queryId: "Create subject of Required Asset"
          });
        } catch (e) {
          console.log(e)
          throw e
        }

        // attach Subjects to the Required Asset
        const subjectAttachQuery = attachToRequiredAssetQuery(id, 'subjects', subjectIris );
        try {
          await dataSources.Stardog.create({
            dbName,
            queryId: "Add Subjects to Required Assets",
            sparqlQuery: subjectAttachQuery
          });
        } catch (e) {
          console.log(e)
          throw e
        }
      }

      // Attach any link(s) supplied to the Required Asset
      if (links !== undefined && links.length > 0) {
        let attachQuery = attachToRequiredAssetQuery( id, 'links', links);
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: attachQuery,
          queryId: "Attach the link(s) to the Required Asset"
        });
      }

      // Attach any remark(s) supplied to the Required Asset
      if (remarks !== undefined && links.length > 0 ) {
        let attachQuery = attachToRequiredAssetQuery( id, 'remarks', remarks);
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: attachQuery,
          queryId: "Attach the remark(s) to the Required Asset"
        });
      }
      
      // retrieve information about the newly created Characterization to return to the user
      const select = selectRequiredAssetQuery(id, selectMap.getNode("createRequiredAsset"));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery: select,
          queryId: "Select Required Asset",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }
      const reducer = getReducer("REQUIRED-ASSET");
      return reducer(response[0]);
    },
    deleteRequiredAsset: async ( _, {remediationId, id}, {dbName, dataSources} ) => {
      // check that the risk response exists
      const sparqlQuery = selectRequiredAssetQuery(id, null);
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

      if (response.length === 0) throw new UserInputError(`Entity does not exist with ID ${id}`);
      let reducer = getReducer("REQUIRED-ASSET");
      const requiredAsset = (reducer(response[0]));
      
      // Delete any attached origins
      if (requiredAsset.hasOwnProperty('subjects_iri')) {
        for (const subjectIri of requiredAsset.subjects_iri) {
          const subjectQuery = deleteSubjectByIriQuery(subjectIri);
          try {
            await dataSources.Stardog.delete({
              dbName,
              sparqlQuery: subjectQuery,
              queryId: "Delete Subject from Required Asset"
            });
          } catch (e) {
            console.log(e)
            throw e
          }    
        }
      }

      // detach the Required Asset from the Risk Response
      if (remediationId !== undefined && remediationId !== null) {
        const iri = `http://csrc.nist.gov/ns/oscal/assessment/common#RequiredAsset-${id}`
        const detachQuery = detachFromRiskResponseQuery( remediationId, 'required_assets', iri );
        try {
          await dataSources.Stardog.delete({
            dbName,
            sparqlQuery: detachQuery,
            queryId: "Detach Required Asset from Risk Response"
          });
        } catch (e) {
          console.log(e)
          throw e
        }
      }
      
      // Delete the characterization itself
      const query = deleteRequiredAssetQuery(id);
      try {
        await dataSources.Stardog.delete({
          dbName,
          sparqlQuery: query,
          queryId: "Delete Required Asset"
        });
      } catch (e) {
        console.log(e)
        throw e
      }
      return id;
    },
    editRiskResponse: async (_, {id, input}, {dbName, dataSources, selectMap}) => {
      const query = updateQuery(
        `http://csrc.nist.gov/ns/oscal/assessment/common#RequiredAsset-${id}`,
        "http://csrc.nist.gov/ns/oscal/assessment/common#RequiredAsset",
        input,
        requiredAssetPredicateMap
      )
      await dataSources.Stardog.edit({
        dbName,
        sparqlQuery: query,
        queryId: "Update Required Asset"
      });
      const select = selectRequiredAssetQuery(id, selectMap.getNode("editRequiredAsset"));
      const result = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery: select,
        queryId: "Select Required Asset",
        singularizeSchema
      });
      const reducer = getReducer("REQUIRED-ASSET");
      return reducer(result[0]);
    },
  },
  RequiredAsset: {
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
    subjects: async (parent, _, {dbName, dataSources, selectMap}) => {
      if (parent.subjects_iri === undefined) return [];
      let iriArray = parent.subjects_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getReducer("SUBJECT");
        for (let iri of iriArray) {
          if (iri === undefined || !iri.includes('Subject')) {
            continue;
          }
          const sparqlQuery = selectSubjectByIriQuery(iri, selectMap.getNode("subjects"));
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: "Select Subject",
              singularizeSchema
            });
          } catch (e) {
            console.log(e)
            throw e
          }
          if (response === undefined) return [];
          if (Array.isArray(response) && response.length > 0) {
            if (response[0].subject_ref[0].includes('OperatingSystem')) {
              console.error(`[CYIO] INVALID-IRI: ${response[0].iri} 'subject_ref' contains an IRI ${response[0].subject_ref[0]} which is invalid; skipping`);
              continue;
            }

            // determine the actual IRI of the object referenced
            let result;
            let sparqlQuery = selectObjectByIriQuery(response[0].subject_ref[0], response[0].subject_type, ['id'] );
            try {
              result = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: "Obtaining Subject IRI",
              singularizeSchema
              });
            } catch (e) {
                console.log(e)
                throw e
            }
            if (result === undefined || result.length === 0) {
              console.error(`[CYIO] NON-EXISTENT: (${dbName}) '${response[0].subject_ref[0]}'; skipping Subject '${response[0].iri}`);              
              continue;
            }
            results.push(reducer(response[0]));
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

export default requiredAssetResolvers;