import {riskSingularizeSchema as singularizeSchema } from '../../risk-mappings.js';
import {objectMap, selectObjectIriByIdQuery, selectObjectByIriQuery} from '../../../global/global-utils.js';
import {compareValues, updateQuery, filterValues,CyioError} from '../../../utils.js';
import {UserInputError} from "apollo-server-express";
import {
  selectExternalReferenceByIriQuery,
  selectNoteByIriQuery,
  getReducer as getGlobalReducer,
} from '../../../global/resolvers/sparql-query.js';
import { 
  getReducer as getCommonReducer,
  // selectObjectByIriQuery,
} from '../../oscal-common/resolvers/sparql-query.js';
import {
  getReducer, 
  selectAllSubjects,
  deleteSubjectQuery,
  deleteSubjectByIriQuery,
  insertSubjectQuery,
  selectSubjectQuery,
  selectSubjectByIriQuery,
  detachFromSubjectQuery,
  subjectPredicateMap,
  insertSubjectsQuery,
} from './sparql-query.js';


const subjectResolvers = {
  Query: {
    subjects: async (_, args, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectAllSubjects(selectMap.getNode("node"), args);
      let response;
      try {
        response = await dataSources.Stardog.queryAll({
          dbName,
          sparqlQuery,
          queryId: "Select Subject List",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const edges = [];
        const reducer = getReducer("SUBJECT");
        let skipCount = 0, filterCount, resultCount, limit, offset, limitSize, offsetSize;
        limitSize = limit = (args.first === undefined ? response.length : args.first) ;
        offsetSize = offset = (args.offset === undefined ? 0 : args.offset) ;
        filterCount = 0;
        let subjectList ;
        if (args.orderedBy !== undefined ) {
          subjectList = response.sort(compareValues(args.orderedBy, args.orderMode ));
        } else {
          subjectList = response;
        }

        if (offset > subjectList.length) return null;

        // for each Subject in the result set
        for (let subject of subjectList) {
          // skip down past the offset
          if (offset) {
            offset--
            continue
          }

          if (!subject.hasOwnProperty('id') || subject.id === undefined || subject.id === null ) {
            console.warn(`[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${subject.iri} missing field 'id'; skipping`);
            skipCount++;
            continue;
          }
  
          if (!subject.hasOwnProperty('subject_ref') || subject.subject_ref === undefined) {
            console.warn(`[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${subject.iri} missing field 'subject_ref'; skipping`);
            skipCount++;
            continue;
          }
  
          if (!subject.hasOwnProperty('subject_id') && (!subject.hasOwnProperty('subject_name') || subject.subject_name === 'undefined')) {
            // logApp.warn(`[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${subject.iri} missing field 'subject_id'; skipping`);
            console.warn(`[CYIO] DATA-CORRUPTION: (${dbName}) ${subject.iri} referencing missing object '${subject.subject_ref}'; skipping`);
            skipCount++;
            continue;
          }
  
          if (!subject.hasOwnProperty('subject_id') || subject.subject_id === undefined) {
            // logApp.warn(`[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${subject.iri} missing field 'subject_id'; skipping`);
            console.warn(`[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${subject.iri} missing field 'subject_id'; skipping`);
            skipCount++;
            continue;
          }
          if (!subject.hasOwnProperty('subject_name') || subject.subject_name === undefined) {
            console.warn(`[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${subject.iri} missing field 'subject_name'; skipping`);
            skipCount++;
            continue;
          }
  
          // filter out non-matching entries if a filter is to be applied
          if ('filters' in args && args.filters != null && args.filters.length > 0) {
            if (!filterValues(subject, args.filters, args.filterMode) ) {
              continue
            }
            filterCount++;
          }

          // if haven't reached limit to be returned
          if (limit) {
            let edge = {
              cursor: subject.iri,
              node: reducer(subject),
            }
            edges.push(edge)
            limit--;
            if (limit === 0) break;
          }
        }
        // check if there is data to be returned
        if (edges.length === 0 ) return null;
        let hasNextPage = false, hasPreviousPage = false;
        resultCount = subjectList.length - skipCount;
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
    subject: async (_, {id}, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectSubjectQuery(id, selectMap.getNode("subject"));
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

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
          const reducer = getReducer("SUBJECT");
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
    assessmentSubjects: async (_, args, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectAllAssessmentSubjects(selectMap.getNode("node"), args);
      let response;
      try {
        response = await dataSources.Stardog.queryAll({
          dbName,
          sparqlQuery,
          queryId: "Select Assessment Subject List",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const edges = [];
        const reducer = getReducer("ASSESSMENT-SUBJECT");
        let filterCount, resultCount, limit, offset, limitSize, offsetSize;
        limitSize = limit = (args.first === undefined ? response.length : args.first) ;
        offsetSize = offset = (args.offset === undefined ? 0 : args.offset) ;
        filterCount = 0;
        let subjectList ;
        if (args.orderedBy !== undefined ) {
          subjectList = response.sort(compareValues(args.orderedBy, args.orderMode ));
        } else {
          subjectList = response;
        }

        if (offset > subjectList.length) return null;

        // for each Subject in the result set
        for (let subject of subjectList) {
          // skip down past the offset
          if (offset) {
            offset--
            continue
          }

          if (subject.id === undefined || subject.id == null ) {
            console.log(`[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${subject.iri} missing field 'id'; skipping`);
            continue;
          }

          // filter out non-matching entries if a filter is to be applied
          if ('filters' in args && args.filters != null && args.filters.length > 0) {
            if (!filterValues(subject, args.filters, args.filterMode) ) {
              continue
            }
            filterCount++;
          }

          // if haven't reached limit to be returned
          if (limit) {
            let edge = {
              cursor: subject.iri,
              node: reducer(subject),
            }
            edges.push(edge)
            limit--;
            if (limit === 0) break;
          }
        }
        // check if there is data to be returned
        if (edges.length === 0 ) return null;
        let hasNextPage = false, hasPreviousPage = false;
        resultCount = subjectList.length;
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
    assessmentSubject: async (_, {id}, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectAssessmentSubjectQuery(id, selectMap.getNode("assessmentSubject"));
      let response;
      try {
          response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: "Select Assessment Subject",
          singularizeSchema
          });
      } catch (e) {
          console.log(e)
          throw e
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
          const reducer = getReducer("ASSESSMENT-SUBJECT");
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
    createSubject: async ( _, {input}, {dbName, selectMap, dataSources} ) => {
      // convert subject_uuid to IRI
      let result;
      // determine the actual IRI of the object referenced
      let sparqlQuery = selectObjectIriByIdQuery( input.subject_ref, input.subject_type );
      try {
        result = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery,
        queryId: "Select Subject target",
        singularizeSchema
        });
      } catch (e) {
          console.log(e)
          throw e
      }
      if (result === undefined || result.length === 0) throw new CyioError(`Entity does not exist with ID ${input.subject_ref}`);
      input.subject_ref = result[0].iri;

      // create the Subject
      const {id, query} = insertSubjectQuery(input);
      try {
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: query,
          queryId: "Create Subject"
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      // retrieve information about the newly created Characterization to return to the user
      const select = selectSubjectQuery(id, selectMap.getNode("createSubject"));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery: select,
          queryId: "Select Subject",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }
      const reducer = getReducer("SUBJECT");
      return reducer(response[0]);
    },
    deleteSubject: async ( _, {id}, {dbName, dataSources} ) => {
      // check that the Subject exists
      const sparqlQuery = selectSubjectQuery(id, null);
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

      if (response.length === 0) throw new CyioError(`Entity does not exist with ID ${id}`);
      let reducer = getReducer("SUBJECT");
      const subject = (reducer(response[0]));
      
      // Detach any attached subject targets
      if (subject.hasOwnProperty('subject_ref_iri')) {
        const subjectIri = subject.subject_ref_iri;
        const subjectQuery = detachFromSubjectQuery(id, 'subject', subjectIri);
        try {
          await dataSources.Stardog.delete({
            dbName,
            sparqlQuery: subjectQuery,
            queryId: "Detaching subject target from Subject"
          });
        } catch (e) {
          console.log(e)
          throw e
        }    
      }

      // Delete the Subject itself
      const query = deleteSubjectQuery(id);
      try {
        await dataSources.Stardog.delete({
          dbName,
          sparqlQuery: query,
          queryId: "Delete Subject"
        });
      } catch (e) {
        console.log(e)
        throw e
      }
      return id;
    },
    editSubject: async (_, {id, input}, {dbName, dataSources, selectMap}) => {
      // make sure there is input data containing what is to be edited
      if (input === undefined || input.length === 0) throw new CyioError(`No input data was supplied`);

      // TODO: WORKAROUND to remove immutable fields
      input = input.filter(element => (element.key !== 'id' && element.key !== 'created' && element.key !== 'modified'));

      // check that the object to be edited exists with the predicates - only get the minimum of data
      let editSelect = ['id'];
      for (let editItem of input) {
        editSelect.push(editItem.key);
      }

      const sparqlQuery = selectSubjectQuery(id, editSelect );
      let response = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery,
        queryId: "Select Subject",
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

      const query = updateQuery(
        `http://csrc.nist.gov/ns/oscal/assessment/common#Subject-${id}`,
        "http://csrc.nist.gov/ns/oscal/assessment/common#Subject",
        input,
        subjectPredicateMap
      );
      if (query !== null) {
        let response;
        try {
          response = await dataSources.Stardog.edit({
            dbName,
            sparqlQuery: query,
            queryId: "Update OSCAL Subject"
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

      const select = selectSubjectQuery(id, selectMap.getNode("editSubject"));
      const result = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery: select,
        queryId: "Select Subject",
        singularizeSchema
      });
      const reducer = getReducer("SUBJECT");
      return reducer(result[0]);
    },
    createAssessmentSubject: async ( _, {input}, {dbName, selectMap, dataSources} ) => {
      if (input.include_all !== undefined && input.include_subjects !== undefined) {
        throw new CyioError(`Can not specify both 'include_all' and 'include_subjects'`);
      }

      // Setup to handle embedded objects to be created
      let includes, excludes;
      if (input.include_subjects !== undefined) {
        includes = input.include_subjects;
        delete input.include_subjects;
      }
      if (input.exclude_subjects !== undefined) {
        excludes = input.exclude_subjects;
        delete input.exclude_subjects;
      }

      // create the Assessment Subject
      const {id, query} = insertAssessmentSubjectQuery(input);
      await dataSources.Stardog.create({
        dbName,
        sparqlQuery: query,
        queryId: "Create Assessment Subject"
      });

      // Add the Subjects to be included to the Assessment Subject
      if (includes !== undefined && includes !== null ) {
        // Create the Subject
        const { includeIris, query } = insertSubjectsQuery( includes );
        try {
          await dataSources.Stardog.create({
            dbName,
            sparqlQuery: query,
            queryId: "Create Subjects of AssessmentSubject"
          });
        } catch (e) {
          console.log(e)
          throw e
        }

        // Attach the Subject to the Assessment Subject include list
        const includeAttachQuery = attachToAssessmentSubjectQuery(id, 'include_subjects', includeIris );
        try {
          await dataSources.Stardog.create({
            dbName,
            queryId: "Add Subjects to AssessmentSubject",
            sparqlQuery: includeAttachQuery
          });
        } catch (e) {
          console.log(e)
          throw e
        }
      }
      // Add the Subjects to be excluded to the Assessment Subject
      if (excludes !== undefined && excludes !== null ) {
        // Create the Subject
        const { excludeIris, query } = insertSubjectsQuery( excludes );
        try {
          await dataSources.Stardog.create({
            dbName,
            sparqlQuery: query,
            queryId: "Create Subjects of AssessmentSubject"
          });
        } catch (e) {
          console.log(e)
          throw e
        }

        // Attach the Subject to the Assessment Subject exclude list
        const includeAttachQuery = attachToAssessmentSubjectQuery(id, 'exclude_subjects', excludeIris );
        try {
          await dataSources.Stardog.create({
            dbName,
            queryId: "Add Subject to Assessment Subject",
            sparqlQuery: includeAttachQuery
          });
        } catch (e) {
          console.log(e)
          throw e
        }
      }

      // retrieve information about the newly created Assessment to return to the caller
      const select = selectAssessmentSubjectQuery(id, selectMap.getNode("createAssessmentSubject"));
      const result = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery: select,
        queryId: "Select Assessment Subject",
        singularizeSchema
      });
      const reducer = getReducer("ASSESSMENT-SUBJECT");
      return reducer(result[0]);
    },
    deleteAssessmentSubject: async ( _, {id}, {dbName, dataSources} ) => {
      // check that the AssessmentSubject exists
      const sparqlQuery = selectAssessmentSubjectQuery(id, null);
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: "Select AssessmentSubject",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      if (response.length === 0) throw new CyioError(`Entity does not exist with ID ${id}`);
      let reducer = getReducer("ASSESSMENT-SUBJECT");
      const subject = (reducer(response[0]));
      
      // Delete any attached Subjects included
      if (subject.include_subjects_iri !== undefined && subject.include_subjects_iri != null) {
        for (let subjectIri of subject.include_subjects_iri ) {
          let subQuery = deleteSubjectByIriQuery( subjectIri );
          try {
            await dataSources.Stardog.delete({
              dbName,
              sparqlQuery: subQuery,
              queryId: "Delete included Subject from AssessmentSubject"
            });
          } catch (e) {
            console.log(e)
            throw e
          }    
        }
      }
      // Delete any attached Subjects excluded
      if (subject.exclude_subjects_iri !== undefined && subject.exclude_subjects_iri != null) {
        for (let subjectIri of subject.exclude_subjects_iri ) {
          let subQuery = deleteSubjectByIriQuery( subjectIri );
          try {
            await dataSources.Stardog.delete({
              dbName,
              sparqlQuery: subQuery,
              queryId: "Delete excluded Subject from AssessmentSubject"
            });
          } catch (e) {
            console.log(e)
            throw e
          }    
        }
      }

      // Delete the Subject itself
      const query = deleteAssessmentSubjectQuery(id);
      try {
        await dataSources.Stardog.delete({
          dbName,
          sparqlQuery: query,
          queryId: "Delete Assessment Subject"
        });
      } catch (e) {
        console.log(e)
        throw e
      }
      return id;
    },
    editAssessmentSubject: async (_, {id, input}, {dbName, dataSources, selectMap}) => {
      // make sure there is input data containing what is to be edited
      if (input === undefined || input.length === 0) throw new CyioError(`No input data was supplied`);

      // TODO: WORKAROUND to remove immutable fields
      input = input.filter(element => (element.key !== 'id' && element.key !== 'created' && element.key !== 'modified'));

      // check that the object to be edited exists with the predicates - only get the minimum of data
      let editSelect = ['id'];
      for (let editItem of input) {
        editSelect.push(editItem.key);
      }

      const sparqlQuery = selectAssessmentSubjectQuery(id, editSelect );
      let response = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery,
        queryId: "Select Assessment Subject",
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

      const query = updateQuery(
        `http://csrc.nist.gov/ns/oscal/assessment/common#AssessmentSubject-${id}`,
        "http://csrc.nist.gov/ns/oscal/assessment/common#AssessmentSubject",
        input,
        subjectPredicateMap
      );
      if (query !== null) {
        let response;
        try {
          response = await dataSources.Stardog.edit({
            dbName,
            sparqlQuery: query,
            queryId: "Update OSCAL Assessment Subject"
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

      const select = selectSubjectQuery(id, selectMap.getNode("editAssessmentSubject"));
      const result = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery: select,
        queryId: "Select AssessmentSubject",
        singularizeSchema
      });
      const reducer = getReducer("ASSESSMENT-SUBJECT");
      return reducer(result[0]);
    },
  },
  Subject: {
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
    subject_ref: async (parent, _, {dbName, dataSources, selectMap }) => {
      if (parent.subject_ref_iri === undefined) return null;
      if( Array.isArray(parent.subject_ref_iri) && parent.subject_ref_iri.length > 1) {
        console.log(`[CYIO] CONSTRAINT-VIOLATION: ${parent.iri} 'subject_ref' violates maxCount constraint; dropping extras`);
      }

      let reducer = getCommonReducer(parent.subject_type.toUpperCase());
      let iri;
      if (Array.isArray(parent.subject_ref_iri)) {
        iri = parent.subject_ref_iri[0];
      } else {
        iri = parent.subject_ref_iri;
      }

      // If all the necessary pieces are here, just build the subject and return it
      let select = selectMap.getNode("subject_ref");
      if (select !== undefined && (select.length === 1 && select.includes('__typename'))) select = undefined;
      if ( parent.hasOwnProperty('subject_id') && parent.hasOwnProperty('subject_name')) {
        let subjectRef = {
          iri: `${iri}`,
          id: `${parent.subject_id}`,
          entity_type: `${parent.subject_type}`,
          name: (parent.subject_version !== undefined) ? `${parent.subject_name} ${parent.subject_version}` : `${parent.subject_name}`,
        }
        if (parent.hasOwnProperty('subject_asset_type')) subjectRef.asset_type = parent.subject_asset_type;
        if (parent.hasOwnProperty('subject_component_type')) subjectRef.component_type = parent.subject_component_type;
        if (parent.hasOwnProperty('subject_location_type')) subjectRef.location_type = parent.subject_location_type;
        if (parent.hasOwnProperty('subject_party_type')) subjectRef.party_type = parent.subject_party_type;
        return reducer( subjectRef );
      }

      if (select === undefined) {
        select = ['iri','id','name','object_type'];
        switch(parent.subject_type) {
          case 'component':
            select.push('component_type');
            select.push('asset_type');
            break;
          case 'inventory-item':
            select.push('asset_type');
            break;
          case 'oscal-location':
          case 'location':
            select.push('location_type');
            break;
          case 'oscal-party':
          case 'party':
            select.push('party_type');
            break;
          case 'oscal-user':
          case 'user':
            select.push('user_type');
            break;
        }
      }
      const sparqlQuery = selectObjectByIriQuery(iri, parent.subject_type, select);
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: "Select Object",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }
      if (response === undefined || response.length === 0) return null;
      if (Array.isArray(response) && response.length > 0) {
        if (response[0].id === undefined) {
          console.log(`[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${response[0].iri} required field 'id' is missing; skipping`);
          return null;
        }

        return (reducer(response[0]))
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
    },    
  },
  AssessmentSubject: {
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
    include_subjects: async (parent, _, {dbName, dataSources, selectMap}) => {
      if (parent.include_subjects_iri === undefined) return [];
      const results = [];
      const reducer = getReducer("SUBJECT");
      let sparqlQuery = selectAllSubjects(selectMap.getNode('include_subjects'), undefined, parent);
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: "Select Referenced Subjects to be included",
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
        results.push(reducer(subject));
      }

      // check if there is data to be returned
      if (results.length === 0 ) return [];
      return results;
    },
    exclude_subjects: async (parent, _, {dbName, dataSources, selectMap}) => {
      if (parent.exclude_subjects_iri === undefined) return [];
      const results = [];
      const reducer = getReducer("SUBJECT");
      let sparqlQuery = selectAllSubjects(selectMap.getNode('exclude_subjects'), undefined, parent);
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: "Select Referenced Subjects to be excluded",
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
        results.push(reducer(subject));
      }

      // check if there is data to be returned
      if (results.length === 0 ) return [];
      return results;
    },
  },
  SubjectTarget: {
    __resolveType: (item) => {
      // WORKAROUND: entity_type not being set correctly
      if (item.entity_type === 'location') item.entity_type = 'oscal-location';
      // ENDIF
      return objectMap[item.entity_type].graphQLType;
    }
  }
}

export default subjectResolvers;
