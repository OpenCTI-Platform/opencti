import { riskSingularizeSchema as singularizeSchema } from '../../risk-mappings.js';
import {compareValues, updateQuery, filterValues, CyioError} from '../../../utils.js';
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
  selectAllSubjects,
  selectSubjectByIriQuery,
  detachFromRequiredAssetQuery,
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
          if (result === undefined || result.length === 0) throw new CyioError(`Link object does not exist with ID ${taskId}`);
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
          if (result === undefined || result.length === 0) throw new CyioError(`Remark object does not exist with ID ${taskId}`);
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
  
          if (result == undefined || result.length === 0) throw new CyioError(`Entity does not exist with ID ${subject.subject_ref}`);
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

      if (response.length === 0) throw new CyioError(`Entity does not exist with ID ${id}`);
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
    editRequiredAsset: async (_, {id, input}, {dbName, dataSources, selectMap}) => {
      let targetIri, relationshipQuery, query;

      // make sure there is input data containing what is to be edited
      if (input === undefined || input.length === 0) throw new CyioError(`No input data was supplied`);

      // TODO: WORKAROUND to remove immutable fields
      input = input.filter(element => (element.key !== 'id' && element.key !== 'created' && element.key !== 'modified'));

      // check that the object to be edited exists with the predicates - only get the minimum of data
      let editSelect = ['id','created','modified'];
      for (let editItem of input) {
        editSelect.push(editItem.key);
      }

      query = selectRequiredAssetQuery(id, editSelect);
      const response = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery: query,
        queryId: "Select Required Asset",
        singularizeSchema
      });
      if (response.length === 0) throw new CyioError(`Entity does not exist with ID ${id}`);
      targetIri = response[0].iri;

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
        let value, fieldType, iris=[];
        for (value of editItem.value) {
          switch(editItem.key) {
            case 'subjects':
              fieldType = 'complex';
              let editObjects = JSON.parse(value);
              if (!Array.isArray(editObjects)) editObjects = [editObjects];

              // perform any validations of the input values and convert id's to IRI's
              if (editItem.operation === 'add' || editItem.operation === 'replace') {
                // check if referenced object(s) exists
                for (let subject of editObjects) {
                  let result;
                  try {
                    query = selectObjectIriByIdQuery(subject.subject_ref, subject.subject_type);
                    result = await dataSources.Stardog.queryById({
                      dbName,
                      sparqlQuery: query,
                      queryId: "Select Object",
                      singularizeSchema
                    });
                  } catch (e) {
                    console.log(e)
                    throw e
                  }
                  if (result == undefined || result.length === 0) throw new CyioError(`Entity does not exist with ID ${obj.subject_ref}`);
                  subject.subject_ref = result[0].iri;

                  // check if there is a corresponding replacement subject already exists
                  try {
                    let args = {filters: [{key: 'subject_type', values:[subject.subject_type]}]}
                    query = selectAllSubjects(['iri','id','subject_type','subject_ref'], args);
                    result = await dataSources.Stardog.queryAll({
                      dbName,
                      sparqlQuery: query,
                      queryId: "Select Object",
                      singularizeSchema
                    });
                  } catch (e) {
                    console.log(e)
                    throw e
                  }
                  if (result == undefined || result.length === 0) throw new CyioError(`Entity does not exist with ID ${obj.subject_ref}`);
                  for (let sub of result) {
                    if (sub.subject_type !== subject.subject_type) continue;
                    if (sub.subject_ref[0] == subject.subject_ref) {
                      // add iri and update the subject_ref to indicates it already exits
                      subject.iri = sub.iri;
                      subject.subject_ref = sub.subject_ref[0];
                    }
                  }
                }
              }

              // need to remove existing complex object(s)
              if (editItem.operation !== 'add') {
                let subjects = `<${response[0][editItem.key]}>`;
                try {
                  // detach from the target object
                  query = detachFromRequiredAssetQuery(id, 'subjects', subjects);
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

              // Need to add new complex object(s)
              if (editItem.operation !== 'delete') {
                let subjectIris = [];
                for (let subject of editObjects) {
                  // if no IRI, then we need to create the Subject
                  if (!subject.subject_ref.startsWith('<')) subject.subject_ref = `<${subject.subject_ref}>`;
                  if (!subject.hasOwnProperty('iri')) {
                    const { subjectIris, query } = insertSubjectsQuery( [subject] );
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
                    subject.iri = subjectIris[0];
                  }
                  if (!subject.iri.startsWith('<')) subject.iri = `<${subject.iri}>`;
                  subjectIris.push(subject.iri);
                }

                // attach Subject to the Required Asset
                relationshipQuery = attachToRequiredAssetQuery(id, 'subjects', subjectIris );
                try {
                  await dataSources.Stardog.create({
                    dbName,
                    queryId: "Add Subjects to Required Assets",
                    sparqlQuery: relationshipQuery
                  });
                } catch (e) {
                  console.log(e)
                  throw e
                }
              }

              // set operation value to indicate to skip processing it
              editItem.operation = 'skip';
              break;
            default:
              fieldType = 'simple';
              break;
          }

          if (fieldType === 'id') {
            // do nothing
          }
        }
        if (iris.length > 0) editItem.value = iris;
      }    

      // build composite update query for all edit items
      query = updateQuery(
        `http://csrc.nist.gov/ns/oscal/assessment/common#RequiredAsset-${id}`,
        "http://csrc.nist.gov/ns/oscal/assessment/common#RequiredAsset",
        input,
        requiredAssetPredicateMap
      );
      if (query != null) {
        await dataSources.Stardog.edit({
          dbName,
          sparqlQuery: query,
          queryId: "Update Required Asset"
        });  
      }
      // retrieve the updated contents
      let result;
      try {
        query = selectRequiredAssetQuery(id, selectMap.getNode("editRequiredAsset"));
        result = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery: query,
          queryId: "Select Required Asset",
          singularizeSchema
        });  
      } catch (e) {
        console.log(e)
        throw e
      }

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
      const results = [];
      const reducer = getReducer("SUBJECT");
      let sparqlQuery = selectAllSubjects(selectMap.getNode('subjects'), undefined, parent);
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: "Select Referenced Subjects",
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

      for (let subject of response) {
        if (!subject.hasOwnProperty('id') || subject.id === undefined || subject.id === null ) {
          console.warn(`[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${subject.iri} missing field 'id'; skipping`);
          continue;
        }

        if (!subject.hasOwnProperty('subject_ref') || subject.subject_ref === undefined) {
          console.warn(`[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${subject.iri} missing field 'subject_ref'; skipping`);
          continue;
        }

        if (!subject.hasOwnProperty('subject_id') && (!subject.hasOwnProperty('subject_name') || subject.subject_name === 'undefined')) {
          // logApp.warn(`[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${subject.iri} missing field 'subject_id'; skipping`);
          console.warn(`[CYIO] DATA-CORRUPTION: (${dbName}) ${subject.iri} referencing missing object '${subject.subject_ref}'; skipping`);
          continue;
        }

        if (!subject.hasOwnProperty('subject_id') || subject.subject_id === undefined) {
          // logApp.warn(`[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${subject.iri} missing field 'subject_id'; skipping`);
          console.warn(`[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${subject.iri} missing field 'subject_id'; skipping`);
          continue;
        }
        if (!subject.hasOwnProperty('subject_name') || subject.subject_name === undefined) {
          console.warn(`[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${subject.iri} missing field 'subject_name'; skipping`);
          continue;
        }

        results.push(reducer(subject));
      }

      // check if there is data to be returned
      if (results.length === 0 ) return [];
      return results;
    },
  }
}

export default requiredAssetResolvers;