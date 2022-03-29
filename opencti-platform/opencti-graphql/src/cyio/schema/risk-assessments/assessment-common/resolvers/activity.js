import { riskSingularizeSchema as singularizeSchema } from '../../risk-mappings.js';
import { compareValues, updateQuery, filterValues } from '../../../utils.js';
import { UserInputError } from "apollo-server-express";
import {
  selectLabelByIriQuery,
  selectExternalReferenceByIriQuery,
  selectNoteByIriQuery,
  getReducer as getGlobalReducer,
} from '../../../global/resolvers/sparql-query.js';
import {
  getReducer,
  insertActivityQuery,
  selectActivityQuery,
  selectAllActivities,
  deleteActivityQuery,
  activityPredicateMap,
  insertAssociatedActivityQuery,
  selectAssociatedActivityQuery,
  selectAllAssociatedActivities,
  deleteAssociatedActivityQuery,
  attachToAssociatedActivityQuery,
  detachFromAssociatedActivityQuery,
  selectAssessmentSubjectByIriQuery,
  associatedActivityPredicateMap,
  selectSubjectByIriQuery,
  deleteAssessmentSubjectByIriQuery,
} from './sparql-query.js';
import {
  getReducer as getCommonReducer,
  selectResponsiblePartyByIriQuery,  
} from '../../oscal-common/resolvers/sparql-query.js';


const activityResolvers = {
  Query: {
    activities: async (_, args, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectAllActivities(selectMap.getNode("node"), args.filters);
      let response;
      try {
        response = await dataSources.Stardog.queryAll({
          dbName,
          sparqlQuery,
          queryId: "Select Activities List",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const edges = [];
        const reducer = getReducer("ACTIVITY");
        let limit = (args.first === undefined ? response.length : args.first) ;
        let offset = (args.offset === undefined ? 0 : args.offset) ;
        let activityList ;
        if (args.orderedBy !== undefined ) {
          activityList = response.sort(compareValues(args.orderedBy, args.orderMode ));
        } else {
          activityList = response;
        }

        if (offset > activityList.length) return null;

        // for each Risk in the result set
        for (let activity of activityList) {
          // skip down past the offset
          if (offset) {
            offset--
            continue
          }

          if (activity.id === undefined || activity.id == null ) {
            console.log(`[DATA-ERROR] object ${activity.iri} is missing required properties; skipping object.`);
            continue;
          }

          // filter out non-matching entries if a filter is to be applied
          if ('filters' in args && args.filters != null && args.filters.length > 0) {
            if (!filterValues(activity, args.filters, args.filterMode) ) {
              continue
            }
          }

          // if haven't reached limit to be returned
          if (limit) {
            let edge = {
              cursor: activity.iri,
              node: reducer(activity),
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
            hasNextPage: (args.first > activityList.length),
            hasPreviousPage: (args.offset > 0),
            globalCount: activityList.length,
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
    activity: async (_, {id}, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectActivityQuery(id, selectMap.getNode("activity"));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: "Select Activity",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const reducer = getReducer("ACTIVITY");
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
    associatedActivities: async (_, args, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectAllAssociatedActivities(selectMap.getNode("node"), args.filters);
      let response;
      try {
        response = await dataSources.Stardog.queryAll({
          dbName,
          sparqlQuery,
          queryId: "Select Associated Activities List",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const edges = [];
        const reducer = getReducer("ASSOCIATED-ACTIVITY");
        let limit = (args.first === undefined ? response.length : args.first) ;
        let offset = (args.offset === undefined ? 0 : args.offset) ;
        let assocActivityList ;
        if (args.orderedBy !== undefined ) {
          assocActivityList = response.sort(compareValues(args.orderedBy, args.orderMode ));
        } else {
          assocActivityList = response;
        }

        if (offset > assocActivityList.length) return null;

        // for each Risk in the result set
        for (let activity of assocActivityList) {
          // skip down past the offset
          if (offset) {
            offset--
            continue
          }

          if (activity.id === undefined || activity.id == null ) {
            console.log(`[DATA-ERROR] object ${activity.iri} is missing required properties; skipping object.`);
            continue;
          }

          // filter out non-matching entries if a filter is to be applied
          if ('filters' in args && args.filters != null && args.filters.length > 0) {
            if (!filterValues(activity, args.filters, args.filterMode) ) {
              continue
            }
          }

          // if haven't reached limit to be returned
          if (limit) {
            let edge = {
              cursor: activity.iri,
              node: reducer(activity),
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
            hasNextPage: (args.first > assocActivityList.length),
            hasPreviousPage: (args.offset > 0),
            globalCount: assocActivityList.length,
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
    associatedActivity: async (_, {id}, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectAssociatedActivityQuery(id, selectMap.getNode("associatedActivity"));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: "Select Associated Activity",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const reducer = getReducer("ASSOCIATED-ACTIVITY");
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
    createActivity: async ( _, {input}, {dbName, selectMap, dataSources} ) => {
      // Setup to handle embedded objects to be created
      let roles, steps, controls;
      if (input.responsible_roles !== undefined ) {
        roles = input.responsible_roles;
        delete input.responsible_roles;
      }
      if (input.steps !== undefined ) {
        steps = input.roles;
        delete input.steps;
      }
      if (input.controls !== undefined ) {
        controls = input.controls;
        delete input.controls;
      }

      // create the Activity
      const {id, query} = insertActivityQuery(input);
      try {
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: query,
          queryId: "Create Activity"
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      // TODO: create any responsible role and attach them
      if (roles !== undefined && roles !== null ) {}

      // TODO: create any steps and attach them
      if (steps !== undefined && steps !== null ) {}

      // TODO: create any controls and attach them
      if (controls !== undefined && controls !== null ) {}
      
      // retrieve information about the newly created Activity to return to the user
      const select = selectActivityQuery(id, selectMap.getNode("createActivity"));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery: select,
          queryId: "Select Activity",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }
      const reducer = getReducer("ACTIVITY");
      return reducer(response[0]);
    },
    deleteActivity: async ( _, {id}, {dbName, dataSources} ) => {
      // check that the Activity exists
      const sparqlQuery = selectActivityQuery(id, null);
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: "Select Activity",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      if (response.length === 0) throw new UserInputError(`Entity does not exist with ID ${id}`);
      const reducer = getReducer("ACTIVITY");
      const activity = (reducer(response[0]));

      // TODO: Delete any Responsible Roles attached
      if (activity.responsible_roles_iri !== undefined && activity.responsible_roles_iri !== null) {
      }

      // TODO: Delete any Steps attached
      if (activity.steps_iri !== undefined && activity.steps_iri !== null) {
      }
      // TODO: Delete any Related Controls attached
      if (activity.related_controls_iri !== undefined && activity.related_controls_iri !== null) {
      }

      // delete the Activity
      const query = deleteActivityQuery(id);
      await dataSources.Stardog.delete({
        dbName,
        sparqlQuery: query,
        queryId: "Delete Activity"
      });
      return id;
    },
    editActivity: async (_, {id, input}, {dbName, dataSources, selectMap}) => {
      // check that the Activity exists
      const sparqlQuery = selectActivityQuery(id, null);
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: "Select Activity",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }
      if (response.length === 0) throw new UserInputError(`Entity does not exist with ID ${id}`);
      const query = updateQuery(
        `http://csrc.nist.gov/ns/oscal/assessment/common#Activity-${id}`,
        "http://csrc.nist.gov/ns/oscal/assessment/common#Activity",
        input,
        activityPredicateMap
      )
      await dataSources.Stardog.edit({
        dbName,
        sparqlQuery: query,
        queryId: "Update Activity"
      });
      const select = selectActivityQuery(id, selectMap.getNode("editActivity"));
      let result;
      try {
        result = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery: select,
          queryId: "Select Activity",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }
      const reducer = getReducer("ACTIVITY");
      return reducer(result[0]);
    },
    createAssociatedActivity: async ( _, {input}, {dbName, selectMap, dataSources} ) => {
      // Setup to handle embedded objects to be created
      let taskId, roles, subjects;
      if (input.task_id !== undefined) taskId = input.task_id;
      if (input.roles !== undefined ) roles = input.roles;
      if (input.subjects !== undefined) subjects = input.subjects;

      // create the Associated Activity
      const {id, query} = insertAssociatedActivityQuery(input);
      try {
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: query,
          queryId: "Create Associated Activity"
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      // add the Associated Activity to the Task
      if (taskId !== undefined && taskId !== null) {
        const attachQuery = attachToTaskQuery( riskId, 'associated_activity', iri );
        try {
          await dataSources.Stardog.create({
            dbName,
            sparqlQuery: attachQuery,
            queryId: "Add Associated Activity to Task"
          });
        } catch (e) {
          console.log(e)
          throw e
        }  
      }
      
      // create any subjects supplied and attach them to the Associated Activity
      if (subjects !== undefined && subjects !== null) {
        //create the Subject
        const {subjectIris, query } = insertAssessmentSubjectsQuery(subjects);
        try {
          await dataSources.Stardog.create({
            dbName,
            sparqlQuery: query,
            queryId: "Create Assessment Subjects of Associated Activity"
          });
        } catch (e) {
          console.log(e)
          throw e
        }

        // attach the Subject to the Associated Activity
        const subjectAttachQuery = attachToAssociatedActivityQuery(id, 'subjects', subjectIris );
        try {
          await dataSources.Stardog.create({
            dbName,
            queryId: "Add Assessment Subject(s) to Associated Activity",
            sparqlQuery: subjectAttachQuery
          });
        } catch (e) {
          console.log(e)
          throw e
        }
      }

      // create any Responsible Roles and attach them to the Associated Activity
      if (roles !== undefined && roles !== null) {
        // TODO: create the Responsible Role

        // TODO: Attach the Responsible Role to the Associated Activity
      }

      // retrieve information about the newly created Activity to return to the user
      const select = selectAssociatedActivityQuery(id, selectMap.getNode("createAssociatedActivity"));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery: select,
          queryId: "Select Associated Activity",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }
      const reducer = getReducer("ASSOCIATED-ACTIVITY");
      return reducer(response[0]);
    },
    deleteAssociatedActivity: async ( _, {taskId, id}, {dbName, dataSources} ) => {
      // check that the Activity exists
      const sparqlQuery = selectAssociatedActivityQuery(id, null);
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: "Select Associated Activity",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }
      if (response.length === 0) throw new UserInputError(`Entity does not exist with ID ${id}`);
      const reducer = getReducer("ASSOCIATED-ACTIVITY");
      const activity = reducer(response[0]);

      // Delete the attached Assessment Subjects
      if (activity.subjects_iri !== undefined && activity.subjects_iri !== null) {
        // Delete the Assessment Subjects
        for (let subjectIri of activity.subjects_iri) {
          let subQuery = deleteAssessmentSubjectByIriQuery( subjectIri);
          await dataSources.Stardog.delete({
            dbName,
            sparqlQuery: subQuery,
            queryId: "Delete Assessment Subject"
          });
        }
      }

      // delete the Activity
      const query = deleteAssociatedActivityQuery(id);
      await dataSources.Stardog.delete({
        dbName,
        sparqlQuery: query,
        queryId: "Delete Associated Activity"
      });
      return id;
    },
    editAssociatedActivity: async (_, {id, input}, {dbName, dataSources, selectMap}) => {
      // check that the Activity exists
      const sparqlQuery = selectAssociatedActivityQuery(id, null);
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: "Select Associated Activity",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }
      if (response.length === 0) throw new UserInputError(`Entity does not exist with ID ${id}`);
      const query = updateQuery(
        `http://csrc.nist.gov/ns/oscal/assessment/common#AssociatedActivity-${id}`,
        "http://csrc.nist.gov/ns/oscal/assessment/common#AssociatedActivity",
        input,
        associatedActivityPredicateMap
      )
      await dataSources.Stardog.edit({
        dbName,
        sparqlQuery: query,
        queryId: "Update Associated Activity"
      });
      const select = selectActivityQuery(id, selectMap.getNode("editAssociatedActivity"));
      let result;
      try {
        result = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery: select,
          queryId: "Select Associated Activity",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }
      const reducer = getReducer("ASSOCIATED-ACTIVITY");
      return reducer(result[0]);
    },   
  },
  // field-level resolvers
  Activity: {
    labels: async (parent, args, {dbName, dataSources, selectMap}) => {
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
    links: async (parent, args, {dbName, dataSources, selectMap}) => {
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
    remarks: async (parent, args, {dbName, dataSources, selectMap}) => {
      let iriArray = parent.notes_iri;
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
    responsible_roles: async (parent, args, {dbName, dataSources, selectMap}) => {
      let iriArray = parent.notes_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getCommonReducer("RESPONSIBLE-PARTY");
        for (let iri of iriArray) {
          if (iri === undefined || !iri.includes('ResponsibleParty')) {
            continue;
          }
          const sparqlQuery = selectResponsiblePartyByIriQuery(iri, selectMap.getNode("responsible_roles"));
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
  },
  AssociatedActivity: {
    links: async (parent, args, {dbName, dataSources, selectMap}) => {
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
    remarks: async (parent, args, {dbName, dataSources, selectMap}) => {
      let iriArray = parent.notes_iri;
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
    responsible_roles: async (parent, args, {dbName, dataSources, selectMap}) => {
      let iriArray = parent.notes_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getCommonReducer("RESPONSIBLE-PARTY");
        for (let iri of iriArray) {
          if (iri === undefined || !iri.includes('ResponsibleParty')) {
            continue;
          }
          const sparqlQuery = selectResponsiblePartyByIriQuery(iri, selectMap.getNode("responsible_roles"));
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
    subjects: async (parent, args, {dbName, dataSources, selectMap}) => {
      let iriArray = parent.subjects_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getReducer("ASSESSMENT-SUBJECT");
        for (let iri of iriArray) {
          if (iri === undefined || !iri.includes('AssessmentSubject')) {
            continue;
          }
          const sparqlQuery = selectAssessmentSubjectByIriQuery(iri, selectMap.getNode("subjects"));
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
  },
}

export default activityResolvers;