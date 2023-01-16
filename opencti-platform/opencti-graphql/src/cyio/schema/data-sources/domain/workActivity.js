import { UserInputError } from 'apollo-server-express';
import { checkIfValidUUID, CyioError } from '../../utils.js';
import { unmarshall } from '@aws-sdk/util-dynamodb';
import {
  selectSourceActivityByIdQuery,
  selectIngestProgressByIdQuery,
} from '../schema/dynamodb/workActivity.js';


export const findAllIngestActivities = async (args, dataSources) => {
};

export const findIngestActivityById = async (id, activityId, dataSources) => {
};

export const findSourceActivityById = async (sourceId, since, dataSources) => {
  // ensure the id of the data source is a valid UUID
  if (!checkIfValidUUID(sourceId)) throw new CyioError(`Invalid identifier: ${sourceId}`);

  // Lookup the ingest activity records for this data source by the id of the data source
  let sortOrder
  let data;
  try {
    const queryParams = selectSourceActivityByIdQuery(sourceId, since, 'DESC', 5);
    data = await dataSources.DynamoDB.queryByKey({
      params: queryParams,
      queryId: "Retrieving Ingest Activities"
    });
  } catch (err) {
    console.error(err);
    throw err;
  }

  // for each activity in the data set
  let activities = [];
  for (let dynamoDBRecord of data.Items) {
    let activity = unmarshall(dynamoDBRecord);
    let ingestActivity = {
      id: activity['activity_uid'],
      entity_type: 'ingest-activity',
      created: activity.started_at,
      modified: activity.started_at,
      source: activity['data_source_id'],
      start_time: activity.started_at,
      task_id: activity['task_uid']
    };
    activities.push(ingestActivity);
  }

  // look up the ingest task records for the each activity 
  for (let activity of activities) {
    try {
      const queryParams = selectIngestProgressByIdQuery(activity.task_id, 'DESC', 1);
      data = await dataSources.DynamoDB.queryByKey({
        params: queryParams,
        queryId: "Retrieving Ingest Task Records"
      });
    } catch (err) {
      console.error(err);
      throw err;
    }

    for (let dynamoDBRecord of data.Items) {
      let progress = unmarshall(dynamoDBRecord);
      activity.status = progress['cur_status'];
      activity.operations_completed = progress['cur_progress'];
      activity.total_operations = progress['total_progress'];
      if (progress['cur_status'] === 'completed') activity.completed_time = progress.created_at;
      if (progress.hasOwnProperty('message')) activity.messages = [{message: progress.message}];
      if (progress.hasOwnProperty('error_msg')) activity.errors = [{message: progress.error_msg}];
    }
  }

  return activities;
};

// export const findActivityMessagesById = async (parent, dbName, dataSources, selectMap) => {
//   // ensure the id is a valid UUID
//   if (!checkIfValidUUID(parent.message_ids)) throw new CyioError(`Invalid identifier: ${id}`);  
// };

// export const findActivityErrorsById = async (parent, dbName, dataSources, selectMap) => {
//   // ensure the id is a valid UUID
//   if (!checkIfValidUUID(parent.error_ids)) throw new CyioError(`Invalid identifier: ${id}`);  
// };

// export const findActivityTrackingById = async (parent, dbName, dataSources, selectMap) => {
//   // ensure the id is a valid UUID
//   if (!checkIfValidUUID(parent.tracking_id)) throw new CyioError(`Invalid identifier: ${id}`);  
// };

// export const findInitiatorById = async (parent, dbName, dataSources, selectMap) => {
//   return null;
// };
