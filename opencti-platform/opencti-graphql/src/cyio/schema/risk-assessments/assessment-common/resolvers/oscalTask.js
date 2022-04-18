import { riskSingularizeSchema as singularizeSchema } from '../../risk-mappings.js';
import {compareValues, updateQuery, filterValues, generateId} from '../../../utils.js';
import {UserInputError} from "apollo-server-express";
import {
  selectLabelByIriQuery,
  selectExternalReferenceByIriQuery,
  selectNoteByIriQuery,
  getReducer as getGlobalReducer,
} from '../../../global/resolvers/sparql-query.js';
import {
  deleteResponsiblePartyByIriQuery,
  selectResponsiblePartyByIriQuery,
  getReducer as getCommonReducer,
} from '../../oscal-common/resolvers/sparql-query.js';
import {
  getReducer, 
  insertOscalTaskQuery,
  selectOscalTaskQuery,
  selectOscalTaskByIriQuery,
  selectAllOscalTasks,
  deleteOscalTaskQuery,
  selectAssessmentSubjectByIriQuery,
  deleteAssessmentSubjectByIriQuery,
  deleteAssociatedActivityByIriQuery,
  selectAssociatedActivityByIriQuery,
  oscalTaskPredicateMap,
  attachToOscalTaskQuery,
} from './sparql-query.js';
import { selectObjectIriByIdQuery } from '../../../global/global-utils.js';


const oscalTaskResolvers = {
  Query: {
    oscalTasks: async (_, args, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectAllOscalTasks(selectMap.getNode("node"), args);
      let response;
      try {
        response = await dataSources.Stardog.queryAll({
          dbName,
          sparqlQuery,
          queryId: "Select OSCAL Task List",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const edges = [];
        const reducer = getReducer("TASK");
        let limit = (args.first === undefined ? response.length : args.first) ;
        let offset = (args.offset === undefined ? 0 : args.offset) ;
        let taskList ;
        if (args.orderedBy !== undefined ) {
          taskList = response.sort(compareValues(args.orderedBy, args.orderMode ));
        } else {
          taskList = response;
        }

        if (offset > taskList.length) return null;

        // for each Risk in the result set
        for (let task of taskList) {
          // skip down past the offset
          if (offset) {
            offset--
            continue
          }

          if (task.id === undefined || task.id == null ) {
            console.log(`[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${task.iri} missing field 'id'; skipping`);
            continue;
          }

          // filter out non-matching entries if a filter is to be applied
          if ('filters' in args && args.filters != null && args.filters.length > 0) {
            if (!filterValues(task, args.filters, args.filterMode) ) {
              continue
            }
          }

          // if haven't reached limit to be returned
          if (limit) {
            let edge = {
              cursor: task.iri,
              node: reducer(task),
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
            hasNextPage: (args.first < taskList.length ? true : false),
            hasPreviousPage: (args.offset > 0 ? true : false),
            globalCount: taskList.length,
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
    oscalTask: async (_, {id}, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectOscalTaskQuery(id, selectMap.getNode("oscalTask"));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: "Select OSCAL Task",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const reducer = getReducer("TASK");
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
    }
  },
  Mutation: {
    createOscalTask: async ( _, {input}, {dbName, selectMap, dataSources} ) => {
      // Setup to handle embedded objects to be created
      let dependentTasks = [], relatedTasks = []; 
      let activities, responsibleRoles, assessmentSubjects;
      if (input.timing !== undefined && input.timing !== null) {
        let timing = input.timing;
        delete input.timing;
        if (timing.hasOwnProperty('on_date')) input.on_date = timing.on_date.on_date;
        if (timing.hasOwnProperty('within_date_range')) {
          input.start_date = timing.within_date_range.start_date;
          input.end_date = timing.with_date_range.end_date;
        }
        if (timing.hasOwnProperty('at_frequency')) {
          input.frequency_period = timing.at_frequency.period;
          input.time_unit = timing.at_frequency.unit;
        }
      }
      // obtain the IRIs for the referenced objects so that if one doesn't exists we have created anything yet.
      if (input.task_dependencies !== undefined && input.task_dependencies !== null) {
        for (let taskId of input.task_dependencies) {
          let sparqlQuery = selectObjectIriByIdQuery( taskId, 'oscal-task');
          let result = await dataSources.Stardog.queryById({
            dbName,
            sparqlQuery,
            queryId: "Obtaining IRI for Dependent Task object with id",
            singularizeSchema
          });
          if (result === undefined || result.length === 0) throw new UserInputError(`Entity does not exist with ID ${taskId}`);
          dependentTasks.push(`<${result[0].iri}>`);
        }
        delete input.task_dependencies;
      }
      if (input.related_tasks !== undefined && input.related_tasks !== null) {
        for (let taskId of input.related_tasks) {
          let sparqlQuery = selectObjectIriByIdQuery( taskId, 'oscal-task');
          let result = await dataSources.Stardog.queryById({
            dbName,
            sparqlQuery,
            queryId: "Obtaining IRI for Related Task object with id",
            singularizeSchema
          });
          if (result === undefined || result.length === 0) throw new UserInputError(`Entity does not exist with ID ${taskId}`);
          relatedTasks.push(`<${result[0].iri}>`);
        }
        delete input.related_tasks;
      }
      if (input.responsible_roles !== undefined && input.responsible_roles !== null) {
        responsibleRoles = input.responsible_roles;
        delete input.responsible_roles;
      }
      if (input.associated_activities !== undefined) {
        activities = input.associated_activities;
        delete input.associated_activities;
      }
      if (input.subject !== undefined) {
        assessmentSubjects = input.subjects;
        delete input.subjects;
      }
      // create the Task
      const {id, query} = insertOscalTaskQuery(input);
      await dataSources.Stardog.create({
        dbName,
        sparqlQuery: query,
        queryId: "Create OSCAL Task"
      });

      // Attach any dependent Tasks supplied to the Task
      if (dependentTasks !== undefined && dependentTasks !== null ) {
        // attach task(s) to the Task
        let attachQuery = attachToOscalTaskQuery( id, 'task_dependencies', dependentTasks);
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: attachQuery,
          queryId: "Attach the dependent task(s) to the Task"
        });
      }
      // Attach any related Tasks supplied to the Task
      if (relatedTasks !== undefined && relatedTasks !== null ) {
        // attach task(s) to the Task
        let attachQuery = attachToOscalTaskQuery( id, 'related_tasks', relatedTasks);
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: attachQuery,
          queryId: "Attach the related task(s) to the Task"
        });
      }
      // TODO: create any associated Activities supplied and attach them to the Task
      if (activities !== undefined && activities !== null ) {
        // create the Activity
        // attach Activity to the Task
      }
      // TODO: create any Assessment Subjects supplied and attach them to the Task
      if (assessmentSubjects !== undefined && assessmentSubjects !== null ) {
        // create the Assessment Subject
        // attach Assessment Subject to the Task
      }
      // TODO: create any responsible Roles supplied and attach them to the Task
      if (responsibleRoles !== undefined && responsibleRoles !== null ) {
        // create the Responsible Role
        // attach Responsible Role to the Task
      }

      // retrieve information about the newly created Observation to return to the user
      const select = selectOscalTaskQuery(id, selectMap.getNode("createOscalTask"));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery: select,
          queryId: "Select Task",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }
      const reducer = getReducer("TASK");
      return reducer(response[0]);
    },
    deleteOscalTask: async ( _, {id}, {dbName, dataSources} ) => {
      // check that the Task exists
      const sparqlQuery = selectOscalTaskQuery(id, null);
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: "Select OSCAL Task",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      if (response.length === 0) throw new UserInputError(`Entity does not exist with ID ${id}`);
      let reducer = getReducer("TASK");
      const task = (reducer(response[0]));

      // No need to detach any dependent tasks as they are just references
      // that will get deleted when the Task is deleted

      // Delete any attached activities
      if (task.hasOwnProperty('associated_activities_iri')) {
        for (const activityIri of task.associated_activities_iri) {
          const activityQuery = deleteAssociatedActivityByIriQuery(activityIri);
          try {
            await dataSources.Stardog.delete({
              dbName,
              sparqlQuery: activityQuery,
              queryId: "Delete Associated Activity from the Task"
            });
          } catch (e) {
            console.log(e)
            throw e
          }
        }
      }
      // Delete any attached assessment subjects
      if (task.hasOwnProperty('subjects_iri')) {
        for (const subjectIri of task.subjects_iri) {
          const subjectQuery = deleteAssessmentSubjectByIriQuery(subjectIri);
          try {
            await dataSources.Stardog.delete({
              dbName,
              sparqlQuery: subjectQuery,
              queryId: "Delete Assessment Subject from Task"
            });
          } catch (e) {
            console.log(e)
            throw e
          }    
        }
      }
      // Delete any attached Responsible Roles
      if (task.hasOwnProperty('responsible_roles_iri')) {
        for (const roleIri of task.responsible_roles_iri) {
          const roleQuery = deleteResponsiblePartyByIriQuery(roleIri);
          try {
            await dataSources.Stardog.delete({
              dbName,
              sparqlQuery: roleQuery,
              queryId: "Delete Responsible Roles from Task"
            });
          } catch (e) {
            console.log(e)
            throw e
          }    
        }
      }

      // Detach the Task from its specified parent

      // Delete the Task itself
      const query = deleteOscalTaskQuery(id);
      await dataSources.Stardog.delete({
        dbName,
        sparqlQuery: query,
        queryId: "Delete OSCAL Task"
      });
      return id;
    },
    editOscalTask: async (_, {id, input}, {dbName, dataSources, selectMap}) => {
      const query = updateQuery(
        `http://csrc.nist.gov/ns/oscal/assessment/common#Task-${id}`,
        "http://csrc.nist.gov/ns/oscal/assessment/common#Task",
        input,
        oscalTaskPredicateMap
      )
      await dataSources.Stardog.edit({
        dbName,
        sparqlQuery: query,
        queryId: "Update OSCAL Task"
      });
      const select = selectOscalTaskQuery(id, selectMap.getNode("editOscalTask"));
      const result = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery: select,
        queryId: "Select OSCAL Task",
        singularizeSchema
      });
      const reducer = getReducer("TASK");
      return reducer(result[0]);
    },
  },
  // field-level resolvers
  OscalTask: {
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
    remarks: async (parent, _, {dbName, dataSources, selectMap}) => {
      if (parent.notes_iri === undefined) return [];
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
    // tasks: async (parent, args, {dbName, dataSources, selectMap}) => {},
    task_dependencies: async (parent, _, {dbName, dataSources, selectMap}) => {
      if (parent.task_dependencies_iri === undefined) return [];
      let iriArray = parent.task_dependencies_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getReducer("TASK");
        for (let iri of iriArray) {
          if (iri === undefined || !iri.includes('Task')) {
            continue;
          }
          const sparqlQuery = selectOscalTaskByIriQuery(iri, selectMap.getNode("task_dependencies"));
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: "Select OSCAL Task",
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
    associated_activities: async (parent, _, {dbName, dataSources, selectMap}) => {
      if (parent.associated_activities_iri === undefined) return [];
      let iriArray = parent.associated_activities_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getReducer("ASSOCIATED-ACTIVITY");
        for (let iri of iriArray) {
          if (iri === undefined || !iri.includes('AssociatedActivity')) {
            continue;
          }
          const sparqlQuery = selectAssociatedActivityByIriQuery(iri, selectMap.getNode("associated_activities"));
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
    responsible_roles: async (parent, _, {dbName, dataSources, selectMap}) => {
      if (parent.responsible_roles_iri === undefined) return [];
      let iriArray = parent.responsible_roles_iri;
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
              queryId: "Select Responsible Role",
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
    timing: async (parent, _, ) => {
      const id = generateId( );
      return {
        id: `${id}`,
        entity_type: 'event-timing',
        ...(parent.on_date && {on_date: {date: `${parent.on_date}`}}),
        ...(parent.start_date && {with_date_range: {start_date: `${parent.start_date}`, end_date: `${parent.end_date}`}}),
        ...(parent.frequency_period && {at_frequency: {period: `${parent.frequency_period}`, unit: `${parent.time_unit}`}}),
      }
    }
  }
}

export default oscalTaskResolvers;
