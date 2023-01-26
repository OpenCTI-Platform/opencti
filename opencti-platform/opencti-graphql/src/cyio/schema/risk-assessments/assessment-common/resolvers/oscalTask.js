import { UserInputError } from 'apollo-server-express';
import { riskSingularizeSchema as singularizeSchema } from '../../risk-mappings.js';
import { compareValues, updateQuery, filterValues, generateId, CyioError } from '../../../utils.js';
import { convertToProperties } from '../../riskUtils.js';
import { selectObjectIriByIdQuery, objectMap } from '../../../global/global-utils.js';
import {
  selectLabelByIriQuery,
  selectExternalReferenceByIriQuery,
  selectNoteByIriQuery,
  getReducer as getGlobalReducer,
} from '../../../global/resolvers/sparql-query.js';
import {
  deleteResponsiblePartyByIriQuery,
  selectResponsiblePartyByIriQuery,
  selectAllResponsibleRoles,
  responsiblePartyPredicateMap,
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

const oscalTaskResolvers = {
  Query: {
    oscalTasks: async (_, args, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectAllOscalTasks(selectMap.getNode('node'), args);
      let response;
      try {
        response = await dataSources.Stardog.queryAll({
          dbName,
          sparqlQuery,
          queryId: 'Select OSCAL Task List',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const edges = [];
        const reducer = getReducer('TASK');
        let filterCount;
        let resultCount;
        let limit;
        let offset;
        let limitSize;
        let offsetSize;
        limitSize = limit = args.first === undefined ? response.length : args.first;
        offsetSize = offset = args.offset === undefined ? 0 : args.offset;
        filterCount = 0;
        let taskList;
        if (args.orderedBy !== undefined) {
          taskList = response.sort(compareValues(args.orderedBy, args.orderMode));
        } else {
          taskList = response;
        }

        if (offset > taskList.length) return null;

        // for each Risk in the result set
        for (const task of taskList) {
          // skip down past the offset
          if (offset) {
            offset--;
            continue;
          }

          if (task.id === undefined || task.id == null) {
            console.log(`[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${task.iri} missing field 'id'; skipping`);
            continue;
          }

          // filter out non-matching entries if a filter is to be applied
          if ('filters' in args && args.filters != null && args.filters.length > 0) {
            if (!filterValues(task, args.filters, args.filterMode)) {
              continue;
            }
            filterCount++;
          }

          // if haven't reached limit to be returned
          if (limit) {
            const edge = {
              cursor: task.iri,
              node: reducer(task),
            };
            edges.push(edge);
            limit--;
          }
        }
        // check if there is data to be returned
        if (edges.length === 0) return null;
        let hasNextPage = false;
        let hasPreviousPage = false;
        resultCount = taskList.length;
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
      }
      // Handle reporting Stardog Error
      if (typeof response === 'object' && 'body' in response) {
        throw new UserInputError(response.statusText, {
          error_details: response.body.message ? response.body.message : response.body,
          error_code: response.body.code ? response.body.code : 'N/A',
        });
      } else {
        return null;
      }
    },
    oscalTask: async (_, { id }, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectOscalTaskQuery(id, selectMap.getNode('oscalTask'));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: 'Select OSCAL Task',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const reducer = getReducer('TASK');
        return reducer(response[0]);
      }
      // Handle reporting Stardog Error
      if (typeof response === 'object' && 'body' in response) {
        throw new UserInputError(response.statusText, {
          error_details: response.body.message ? response.body.message : response.body,
          error_code: response.body.code ? response.body.code : 'N/A',
        });
      } else {
        return null;
      }
    },
  },
  Mutation: {
    createOscalTask: async (_, { input }, { dbName, selectMap, dataSources }) => {
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
      const dependentTasks = [];
      const relatedTasks = [];
      const responsibleRoles = [];
      const links = [];
      const remarks = [];
      let activities;
      let assessmentSubjects;
      if (input.timing !== undefined && input.timing !== null) {
        if (
          ('within_date_range' in input.timing && 'on_date' in input.timing) ||
          ('within_date_range' in input.timing && 'at_frequency' in input.timing) ||
          ('on_date in input.timing' && 'at_frequency' in input.timing)
        ) {
          throw new CyioError(`Only one timing field can be specified.`);
        }
        const { timing } = input;
        delete input.timing;
        if ('on_date' in timing) input.on_date = timing.on_date.on_date;
        if ('within_date_range' in timing) {
          input.start_date = timing.within_date_range.start_date;
          if (timing.within_date_range.end_date !== undefined) input.end_date = timing.within_date_range.end_date;
        }
        if ('at_frequency' in timing) {
          input.frequency_period = timing.at_frequency.period;
          input.time_unit = timing.at_frequency.unit;
        }
      }
      // obtain the IRIs for the referenced objects so that if one doesn't exists we have created anything yet.
      if (input.task_dependencies !== undefined && input.task_dependencies !== null) {
        for (const taskId of input.task_dependencies) {
          const sparqlQuery = selectObjectIriByIdQuery(taskId, 'oscal-task');
          const result = await dataSources.Stardog.queryById({
            dbName,
            sparqlQuery,
            queryId: 'Obtaining IRI for Dependent Task object with id',
            singularizeSchema,
          });
          if (result === undefined || result.length === 0)
            throw new CyioError(`Entity does not exist with ID ${taskId}`);
          dependentTasks.push(`<${result[0].iri}>`);
        }
        delete input.task_dependencies;
      }
      if (input.related_tasks !== undefined && input.related_tasks !== null) {
        for (const taskId of input.related_tasks) {
          const sparqlQuery = selectObjectIriByIdQuery(taskId, 'oscal-task');
          const result = await dataSources.Stardog.queryById({
            dbName,
            sparqlQuery,
            queryId: 'Obtaining IRI for Related Task object with id',
            singularizeSchema,
          });
          if (result === undefined || result.length === 0)
            throw new CyioError(`Entity does not exist with ID ${taskId}`);
          relatedTasks.push(`<${result[0].iri}>`);
        }
        delete input.related_tasks;
      }
      if (input.responsible_roles !== undefined && input.responsible_roles !== null) {
        for (const roleId of input.responsible_roles) {
          const sparqlQuery = selectObjectIriByIdQuery(roleId, 'responsible-party');
          const result = await dataSources.Stardog.queryById({
            dbName,
            sparqlQuery,
            queryId: 'Obtaining IRI for Responsible Party object with id',
            singularizeSchema,
          });
          if (result === undefined || result.length === 0)
            throw new CyioError(`Entity does not exist with ID ${roleId}`);
          responsibleRoles.push(`<${result[0].iri}>`);
        }
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
      if (input.links !== undefined && input.links !== null) {
        for (const linkId of input.links) {
          const sparqlQuery = selectObjectIriByIdQuery(linkId, 'link');
          const result = await dataSources.Stardog.queryById({
            dbName,
            sparqlQuery,
            queryId: 'Obtaining IRI for Link object with id',
            singularizeSchema,
          });
          if (result === undefined || result.length === 0)
            throw new CyioError(`Link object does not exist with ID ${taskId}`);
          links.push(`<${result[0].iri}>`);
        }
        delete input.links;
      }
      if (input.remarks !== undefined && input.remarks !== null) {
        for (const remarkId of input.remarks) {
          const sparqlQuery = selectObjectIriByIdQuery(remarkId, 'remark');
          const result = await dataSources.Stardog.queryById({
            dbName,
            sparqlQuery,
            queryId: 'Obtaining IRI for Remark object with id',
            singularizeSchema,
          });
          if (result === undefined || result.length === 0)
            throw new CyioError(`Remark object does not exist with ID ${taskId}`);
          remarks.push(`<${result[0].iri}>`);
        }
        delete input.remarks;
      }

      // create the Task
      const { id, query } = insertOscalTaskQuery(input);
      await dataSources.Stardog.create({
        dbName,
        sparqlQuery: query,
        queryId: 'Create OSCAL Task',
      });

      // Attach any dependent Tasks supplied to the Task
      if (dependentTasks !== undefined && dependentTasks.length > 0) {
        // attach task(s) to the Task
        const attachQuery = attachToOscalTaskQuery(id, 'task_dependencies', dependentTasks);
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: attachQuery,
          queryId: 'Attach the dependent task(s) to the Task',
        });
      }
      // Attach any related Tasks supplied to the Task
      if (relatedTasks !== undefined && relatedTasks.length > 0) {
        // attach task(s) to the Task
        const attachQuery = attachToOscalTaskQuery(id, 'related_tasks', relatedTasks);
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: attachQuery,
          queryId: 'Attach the related task(s) to the Task',
        });
      }
      // TODO: create any associated Activities supplied and attach them to the Task
      if (activities !== undefined && activities !== null) {
        // create the Activity
        // attach Activity to the Task
      }
      // TODO: create any Assessment Subjects supplied and attach them to the Task
      if (assessmentSubjects !== undefined && assessmentSubjects !== null) {
        // create the Assessment Subject
        // attach Assessment Subject to the Task
      }
      if (responsibleRoles !== undefined && responsibleRoles.length > 0) {
        // attach task(s) to the Task
        const attachQuery = attachToOscalTaskQuery(id, 'responsible_roles', responsibleRoles);
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: attachQuery,
          queryId: 'Attach the Responsible Role(s) to the Task',
        });
      }
      // Attach any link(s) supplied to the Task
      if (links !== undefined && links.length > 0) {
        const attachQuery = attachToOscalTaskQuery(id, 'links', links);
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: attachQuery,
          queryId: 'Attach the link(s) to the Task',
        });
      }
      // Attach any remark(s) supplied to the Task
      if (remarks !== undefined && remarks.length > 0) {
        const attachQuery = attachToOscalTaskQuery(id, 'remarks', remarks);
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: attachQuery,
          queryId: 'Attach the remark(s) to the Task',
        });
      }

      // retrieve information about the newly created Observation to return to the user
      const select = selectOscalTaskQuery(id, selectMap.getNode('createOscalTask'));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery: select,
          queryId: 'Select Task',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }
      const reducer = getReducer('TASK');
      return reducer(response[0]);
    },
    deleteOscalTask: async (_, { id }, { dbName, dataSources }) => {
      // check that the Task exists
      const sparqlQuery = selectOscalTaskQuery(id, null);
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: 'Select OSCAL Task',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }

      if (response.length === 0) throw new CyioError(`Entity does not exist with ID ${id}`);
      const reducer = getReducer('TASK');
      const task = reducer(response[0]);

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
              queryId: 'Delete Associated Activity from the Task',
            });
          } catch (e) {
            console.log(e);
            throw e;
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
              queryId: 'Delete Assessment Subject from Task',
            });
          } catch (e) {
            console.log(e);
            throw e;
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
              queryId: 'Delete Responsible Roles from Task',
            });
          } catch (e) {
            console.log(e);
            throw e;
          }
        }
      }

      // Detach the Task from its specified parent

      // Delete the Task itself
      const query = deleteOscalTaskQuery(id);
      await dataSources.Stardog.delete({
        dbName,
        sparqlQuery: query,
        queryId: 'Delete OSCAL Task',
      });
      return id;
    },
    editOscalTask: async (_, { id, input }, { dbName, dataSources, selectMap }) => {
      // make sure there is input data containing what is to be edited
      if (input === undefined || input.length === 0) throw new CyioError(`No input data was supplied`);

      // TODO: WORKAROUND to remove immutable fields
      input = input.filter(
        (element) => element.key !== 'id' && element.key !== 'created' && element.key !== 'modified'
      );

      // check that the object to be edited exists with the predicates - only get the minimum of data
      const editSelect = ['id', 'created', 'modified'];
      for (const editItem of input) {
        editSelect.push(editItem.key);
      }

      const sparqlQuery = selectOscalTaskQuery(id, editSelect);
      const response = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery,
        queryId: 'Select OSCAL Task',
        singularizeSchema,
      });
      if (response.length === 0) throw new CyioError(`Entity does not exist with ID ${id}`);

      // determine operation, if missing
      for (const editItem of input) {
        if (editItem.operation !== undefined) continue;

        // if value if empty then treat as a remove
        if (editItem.value.length === 0) {
          editItem.operation = 'remove';
          continue;
        }
        if (Array.isArray(editItem.value) && editItem.value[0] === null)
          throw new CyioError(`Field "${editItem.key}" has invalid value "null"`);

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
        let value;
        let fieldType;
        let objectType;
        const iris = [];
        for (value of editItem.value) {
          switch (editItem.key) {
            case 'on_date':
            case 'start_date':
            case 'end_date':
            case 'frequency_period':
            case 'time_unit':
              break;

            case 'timing':
              const timing = JSON.parse(value);
              if (
                ('within_date_range' in timing && 'on_date' in timing) ||
                ('within_date_range' in timing && 'at_frequency' in timing) ||
                ('on_date in input.timing' && 'at_frequency' in timing)
              ) {
                throw new CyioError(`Only one timing field can be specified.`);
              }

              let newItem;
              let operationAction = 'replace';

              if ('on_date' in timing) {
                if (!response[0].hasOwnProperty('on_date')) operationAction = 'add';
                if (operationAction !== 'add' && response[0].on_date === timing.on_date.on_date) break;
                newItem = { key: 'on_date', value: timing.on_date.on_date, operation: operationAction };
                input.push(newItem);
              }
              if ('within_date_range' in timing) {
                if (!response[0].hasOwnProperty('start_date')) operationAction = 'add';
                if (operationAction !== 'add' && response[0].start_date === timing.within_date_range.start_date) break;
                newItem = { key: 'start_date', value: timing.within_date_range.start_date, operation: operationAction };
                input.push(newItem);

                if (timing.within_date_range.end_date !== undefined) {
                  if (!response[0].hasOwnProperty('end_date')) operationAction = 'add';
                  if (operationAction !== 'add' && response[0].end_date === timing.within_date_range.end_date) break;
                  newItem = { key: 'end_date', value: timing.within_date_range.end_date, operation: operationAction };
                  input.push(newItem);
                }
              }
              if ('at_frequency' in timing) {
                if (!response[0].hasOwnProperty('frequency_period')) operationAction = 'add';
                if (operationAction !== 'add' && response[0].frequency_period === timing.at_frequency.period) break;
                newItem = { key: 'frequency_period', value: timing.at_frequency.period, operation: operationAction };
                input.push(newItem);

                if (!response[0].hasOwnProperty('time_unit')) operationAction = 'add';
                if (operationAction !== 'add' && response[0].time_unit === timing.at_frequency.unit) break;
                newItem = { key: 'time_unit', value: timing.at_frequency.unit, operation: operationAction };
                input.push(newItem);
              }
              break;

            case 'task_dependencies':
            case 'related_tasks':
              objectType = 'oscal-task';
              fieldType = 'id';
              break;
            case 'responsible_roles':
              objectType = 'oscal-responsible-party';
              fieldType = 'id';
              break;
            case 'links':
              objectType = 'external-reference';
              fieldType = 'id';
              break;
            case 'remarks':
              objectType = 'note';
              fieldType = 'id';
              break;
            case 'associated_activities':
              // TODO: Need to implement when Assessment Subjects are supported
              editItem.operation = 'skip';
              objectType = 'associated-activity';
              fieldType = 'id';
              break;
            case 'subjects':
              // TODO: Need to implement when Assessment Subjects are supported
              editItem.operation = 'skip';
              objectType = 'assessment-subject';
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
              dbName,
              sparqlQuery,
              queryId: 'Obtaining IRI for the object with id',
              singularizeSchema,
            });
            if (result === undefined || result.length === 0)
              throw new CyioError(`Entity does not exist with ID ${taskId}`);
            iris.push(`<${result[0].iri}>`);
          }
        }
        if (iris.length > 0) editItem.value = iris;
      }

      const query = updateQuery(
        `http://csrc.nist.gov/ns/oscal/assessment/common#Task-${id}`,
        'http://csrc.nist.gov/ns/oscal/assessment/common#Task',
        input,
        oscalTaskPredicateMap
      );
      if (query !== null) {
        let response;
        try {
          response = await dataSources.Stardog.edit({
            dbName,
            sparqlQuery: query,
            queryId: 'Update OSCAL Task',
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

      const select = selectOscalTaskQuery(id, selectMap.getNode('editOscalTask'));
      const result = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery: select,
        queryId: 'Select OSCAL Task',
        singularizeSchema,
      });
      const reducer = getReducer('TASK');
      return reducer(result[0]);
    },
  },
  // field-level resolvers
  OscalTask: {
    labels: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.labels_iri === undefined) return [];
      const iriArray = parent.labels_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getGlobalReducer('LABEL');
        for (const iri of iriArray) {
          if (iri === undefined || !iri.includes('Label')) {
            continue;
          }
          const sparqlQuery = selectLabelByIriQuery(iri, selectMap.getNode('labels'));
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: 'Select Label',
              singularizeSchema,
            });
          } catch (e) {
            console.log(e);
            throw e;
          }
          if (response === undefined) return [];
          if (Array.isArray(response) && response.length > 0) {
            results.push(reducer(response[0]));
          } else {
            // Handle reporting Stardog Error
            if (typeof response === 'object' && 'body' in response) {
              throw new UserInputError(response.statusText, {
                error_details: response.body.message ? response.body.message : response.body,
                error_code: response.body.code ? response.body.code : 'N/A',
              });
            }
          }
        }
        return results;
      }
      return [];
    },
    links: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.links_iri === undefined) return [];
      const iriArray = parent.links_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getGlobalReducer('EXTERNAL-REFERENCE');
        for (const iri of iriArray) {
          if (iri === undefined || !iri.includes('ExternalReference')) {
            continue;
          }
          const sparqlQuery = selectExternalReferenceByIriQuery(iri, selectMap.getNode('links'));
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: 'Select Link',
              singularizeSchema,
            });
          } catch (e) {
            console.log(e);
            throw e;
          }
          if (response === undefined) return [];
          if (Array.isArray(response) && response.length > 0) {
            results.push(reducer(response[0]));
          } else {
            // Handle reporting Stardog Error
            if (typeof response === 'object' && 'body' in response) {
              throw new UserInputError(response.statusText, {
                error_details: response.body.message ? response.body.message : response.body,
                error_code: response.body.code ? response.body.code : 'N/A',
              });
            }
          }
        }
        return results;
      }
      return [];
    },
    remarks: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.remarks_iri === undefined) return [];
      const iriArray = parent.remarks_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getGlobalReducer('NOTE');
        for (const iri of iriArray) {
          if (iri === undefined || !iri.includes('Note')) {
            continue;
          }
          const sparqlQuery = selectNoteByIriQuery(iri, selectMap.getNode('remarks'));
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: 'Select Note',
              singularizeSchema,
            });
          } catch (e) {
            console.log(e);
            throw e;
          }
          if (response === undefined) return [];
          if (Array.isArray(response) && response.length > 0) {
            results.push(reducer(response[0]));
          } else {
            // Handle reporting Stardog Error
            if (typeof response === 'object' && 'body' in response) {
              throw new UserInputError(response.statusText, {
                error_details: response.body.message ? response.body.message : response.body,
                error_code: response.body.code ? response.body.code : 'N/A',
              });
            }
          }
        }
        return results;
      }
      return [];
    },
    related_tasks: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.related_tasks_iri === undefined) return [];
      const iriArray = parent.related_tasks_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getReducer('TASK');
        for (const iri of iriArray) {
          if (iri === undefined || !iri.includes('Task')) {
            continue;
          }
          const sparqlQuery = selectOscalTaskByIriQuery(iri, selectMap.getNode('related_tasks'));
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: 'Select OSCAL Task',
              singularizeSchema,
            });
          } catch (e) {
            console.log(e);
            throw e;
          }
          if (response === undefined) return [];
          if (Array.isArray(response) && response.length > 0) {
            results.push(reducer(response[0]));
          } else {
            // Handle reporting Stardog Error
            if (typeof response === 'object' && 'body' in response) {
              throw new UserInputError(response.statusText, {
                error_details: response.body.message ? response.body.message : response.body,
                error_code: response.body.code ? response.body.code : 'N/A',
              });
            }
          }
        }
        return results;
      }
      return [];
    },
    task_dependencies: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.task_dependencies_iri === undefined) return [];
      const iriArray = parent.task_dependencies_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getReducer('TASK');
        for (const iri of iriArray) {
          if (iri === undefined || !iri.includes('Task')) {
            continue;
          }
          const sparqlQuery = selectOscalTaskByIriQuery(iri, selectMap.getNode('task_dependencies'));
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: 'Select OSCAL Task',
              singularizeSchema,
            });
          } catch (e) {
            console.log(e);
            throw e;
          }
          if (response === undefined) return [];
          if (Array.isArray(response) && response.length > 0) {
            results.push(reducer(response[0]));
          } else {
            // Handle reporting Stardog Error
            if (typeof response === 'object' && 'body' in response) {
              throw new UserInputError(response.statusText, {
                error_details: response.body.message ? response.body.message : response.body,
                error_code: response.body.code ? response.body.code : 'N/A',
              });
            }
          }
        }
        return results;
      }
      return [];
    },
    associated_activities: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.associated_activities_iri === undefined) return [];
      const iriArray = parent.associated_activities_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getReducer('ASSOCIATED-ACTIVITY');
        for (const iri of iriArray) {
          if (iri === undefined || !iri.includes('AssociatedActivity')) {
            continue;
          }
          const sparqlQuery = selectAssociatedActivityByIriQuery(iri, selectMap.getNode('associated_activities'));
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: 'Select Associated Activity',
              singularizeSchema,
            });
          } catch (e) {
            console.log(e);
            throw e;
          }
          if (response === undefined) return [];
          if (Array.isArray(response) && response.length > 0) {
            results.push(reducer(response[0]));
          } else {
            // Handle reporting Stardog Error
            if (typeof response === 'object' && 'body' in response) {
              throw new UserInputError(response.statusText, {
                error_details: response.body.message ? response.body.message : response.body,
                error_code: response.body.code ? response.body.code : 'N/A',
              });
            }
          }
        }
        return results;
      }
      return [];
    },
    subjects: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.subjects_iri === undefined) return [];
      const iriArray = parent.subjects_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getReducer('ASSESSMENT-SUBJECT');
        for (const iri of iriArray) {
          if (iri === undefined || !iri.includes('AssessmentSubject')) {
            continue;
          }
          const sparqlQuery = selectAssessmentSubjectByIriQuery(iri, selectMap.getNode('subjects'));
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: 'Select Assessment Subject',
              singularizeSchema,
            });
          } catch (e) {
            console.log(e);
            throw e;
          }
          if (response === undefined) return [];
          if (Array.isArray(response) && response.length > 0) {
            results.push(reducer(response[0]));
          } else {
            // Handle reporting Stardog Error
            if (typeof response === 'object' && 'body' in response) {
              throw new UserInputError(response.statusText, {
                error_details: response.body.message ? response.body.message : response.body,
                error_code: response.body.code ? response.body.code : 'N/A',
              });
            }
          }
        }
        return results;
      }
      return [];
    },
    responsible_roles: async (parent, args, { dbName, dataSources, selectMap }) => {
      if (parent.responsible_roles_iri === undefined) return [];
      const reducer = getCommonReducer('RESPONSIBLE-ROLE');
      const results = [];
      const sparqlQuery = selectAllResponsibleRoles(selectMap.getNode('node'), args, parent);
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: 'Select All Responsible Roles',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }
      if (response === undefined || response.length === 0) return [];

      // Handle reporting Stardog Error
      if (typeof response === 'object' && 'body' in response) {
        throw new UserInputError(response.statusText, {
          error_details: response.body.message ? response.body.message : response.body,
          error_code: response.body.code ? response.body.code : 'N/A',
        });
      }

      for (const item of response) {
        // if props were requested
        if (selectMap.getNode('responsible_roles').includes('props')) {
          const props = convertToProperties(item, responsiblePartyPredicateMap);
          if (props !== null) item.props = props;
        }

        results.push(reducer(item));
      }

      return results;
    },
    timing: async (parent, _) => {
      if (parent.on_date === undefined && parent.start_date === undefined && parent.frequency_period === undefined) {
        return null;
      }
      return {
        ...(parent.on_date && { on_date: parent.on_date }),
        ...(parent.start_date && { start_date: parent.start_date, end_date: parent.end_date }),
        ...(parent.frequency_period && { period: parent.frequency_period, unit: parent.time_unit }),
      };
    },
  },
  EventTiming: {
    __resolveType: (item) => {
      if ('on_date' in item) return 'OnDateTiming';
      if ('start_date' in item) return 'DateRangeTiming';
      if ('period' in item) return 'FrequencyTiming';
    },
  },
};

export default oscalTaskResolvers;
