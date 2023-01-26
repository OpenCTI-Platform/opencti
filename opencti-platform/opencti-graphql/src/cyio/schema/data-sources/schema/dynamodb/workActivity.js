import conf from '../../../../../config/conf.js';

// defines mapping between Javascript type and AWS Attribute types as defined at
// https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_AttributeValue.html
const typeMap = {
  '': 'B', // base64 encoded binary data object
  boolean: 'BOOL', // boolean
  '': 'BS', // array of base64-encoded binary data objects
  '': 'L', // array of AttributeValue objects
  '': 'M', // Map of AttributeValue objects
  number: 'N', // number
  'number-array': 'NS', // array of numbers as strings
  null: 'NULL', // null as a boolean
  string: 'S', // string
  'string-array': 'SS', // array of strings
  undefined: 'NULL',
};

export const selectSourceActivityByIdQuery = (id, since, sortOrder = 'DESC', limitValue) => {
  const tableName = conf.get('dynamodb:tables:ingest-activity:table-name') || 'ingest-activity';
  const partitionKeyName = conf.get('dynamodb:tables:ingest-activity:partition-key-name') || 'data_source_id';
  const sortKeyName = conf.get('dynamodb:tables:ingest-activity:sort-key-name') || 'started_at';
  const daysBack = conf.get('dynamodb:tables:ingest-activity:days-back') || '2';
<<<<<<< HEAD
  const limit = limitValue || 5;
  const ordering = sortOrder.toUpperCase() === 'ASC';
  if (since === undefined) {
=======
  let limit = (limitValue ? limitValue : 5);
  let ordering = (sortOrder.toUpperCase() === 'ASC' ? true : false);
  if (since === undefined || since === null) {
>>>>>>> origin/develop
    since = new Date();
    since.setDate(since.getDate() - parseInt(daysBack));
  }

<<<<<<< HEAD
  const params = {
    TableName: tableName,
    KeyConditionExpression: `${partitionKeyName} = :partitionKey AND ${sortKeyName} >= :sortKey`,
    ExpressionAttributeValues: {
      ':partitionKey': { S: id },
      ':sortKey': { S: since.toISOString() },
=======
  // convert since to a string if its a Date object
  if (since instanceof Date) {
    since = since.toISOString();
  }

  const params =  {
    TableName: tableName,
    KeyConditionExpression: `${partitionKeyName} = :partitionKey AND ${sortKeyName} >= :sortKey`,
    ExpressionAttributeValues: {
      ":partitionKey": { S: id },
      ":sortKey": {S: since},
>>>>>>> origin/develop
    },
    ScanIndexForward: ordering,
    Limit: limit,
  };

  return params;
};

export const selectIngestActivityQuery = (limitValue) => {
  const tableName = conf.get('dynamodb:tables:ingest-activity') || 'ingest-activity';
  const timestamp = new Date().toISOString();
  const limit = limitValue || 5;
  let filterExpression = '';
  const attributeValues = {};
  let count = 1;

  for (const condition of matches) {
    let statement;
    let attrType;
    if (Array.isArray(condition.value)) {
      attrType = typeMap[typeof condition.value[0]];
    } else {
      attrType = typeMap[typeof condition.value];
    }

    switch (condition.expression) {
      case 'BETWEEN':
        attributeValues[`:match${count}`] = { attrType: condition.value[0] };
        attributeValues[`:match${count + 1}`] = { attrType: condition.value[1] };
        statement = `${condition.name} BETWEEN :match${count} AND :match${count + 1}`;
        count++;
        count++;
        break;

      case 'IN':
        statement = `${condition.name} IN (`;
        for (value in condition.value) {
          attributeValues[`:match${count}`] = { attrType: value };
          statement += `:match${count},`;
          count++;
        }
        statement = `${statement.substring(0, statement.length - 1)})`;
        break;

      default:
        attributeValues[`:match${count}`] = { attrType: condition.value };
        statement = `${condition.name} ${condition.comparator} :match${count}`;
        count++;
        if ('expression' in condition) statement += `${expression} `;
        break;
    }
    filterExpression += statement;
  }

  const params = {
    TableName: tableName,
    FilterExpression: filterExpression,
    ExpressionAttributeValues: attributeValues,
    Limit: limit,
  };

  return params;
};

export const createIngestActivityQuery = (id, start_at, itemData) => {
  const tableName = conf.get('dynamodb:tables:ingest-activity') || 'ingest-activity';
  const timestamp = new Date().toISOString();

  const item = {
    data_source_id: { S: id },
    started_at: { S: start_at },
  };

  for (const [key, value] of Object.entries(itemData)) {
    const attrType = getAttributeType(value);
    item[key] = { attrType: value };
  }

  const params = {
    TableName: tableName,
    Item: item,
  };

  return params;
};

export const deleteIngestActivityQuery = (id, start_at) => {
  const tableName = conf.get('dynamodb:tables:ingest-activity') || 'ingest-activity';
  const timestamp = new Date().toISOString();

  const keyInfo = {
    data_source_id: { S: id },
    started_at: { S: start_at },
  };

  const params = {
    TableName: tableName,
    Key: keyInfo,
  };

  return params;
};

export const updateIngestActivityQuery = (id, start_at, itemData) => {
  const tableName = conf.get('dynamodb:tables:ingest-activity') || 'ingest-activity';
  const timestamp = new Date().toISOString();

  const keyInfo = {
    data_source_id: { S: id },
    started_at: { S: start_at },
  };

  const expression = 'set ';
  const attributeValues = {};

  for (const [key, value] of Object.entries(itemData)) {
    const attrType = getAttributeType(value);
    item[key] = { attrType: value };
  }

  const params = {
    TableName: tableName,
    Key: keyInfo,
    UpdateExpression: expression,
    ExpressionAttributeValue: attributeValues,
    ReturnValues: 'ALL_NEW',
  };
};

export const selectIngestProgressByIdQuery = (id, sortOrder = 'DESC', limitValue) => {
  const tableName = conf.get('dynamodb:tables:ingest-task:table-name') || 'ingest-task';
  const partitionKeyName = conf.get(`dynamodb:tables:ingest-task:partition-key-name`) || 'task_uid';
  const sortKeyName = conf.get(`dynamodb:tables:ingest-task:sort-key-name`) || 'created_at';
  const timestamp = new Date().toISOString();
  const limit = limitValue || 5;
  const ordering = sortOrder.toUpperCase() === 'ASC';

  const params = {
    TableName: tableName,
    KeyConditionExpression: `${partitionKeyName} = :partitionKey AND ${sortKeyName} <= :sortKey`,
    ExpressionAttributeValues: {
      ':partitionKey': { S: id },
      ':sortKey': { S: timestamp },
    },
    ScanIndexForward: ordering,
    Limit: limit,
  };

  return params;
};

export const selectIngestProgressQuery = (limitValue) => {
  const tableName = conf.get('dynamodb:tables:ingest-progress') || 'ingest-task';
  const timestamp = new Date().toISOString();
  const limit = limitValue || 5;
  let filterExpression = '';
  const attributeValues = {};
  let count = 1;

  for (const condition of matches) {
    let statement;
    let attrType;
    if (Array.isArray(condition.value)) {
      attrType = typeMap[typeof condition.value[0]];
    } else {
      attrType = typeMap[typeof condition.value];
    }

    switch (condition.expression) {
      case 'BETWEEN':
        attributeValues[`:match${count}`] = { attrType: condition.value[0] };
        attributeValues[`:match${count + 1}`] = { attrType: condition.value[1] };
        statement = `${condition.name} BETWEEN :match${count} AND :match${count + 1}`;
        count++;
        count++;
        break;

      case 'IN':
        statement = `${condition.name} IN (`;
        for (value in condition.value) {
          attributeValues[`:match${count}`] = { attrType: value };
          statement += `:match${count},`;
          count++;
        }
        statement = `${statement.substring(0, statement.length - 1)})`;
        break;

      default:
        attributeValues[`:match${count}`] = { attrType: condition.value };
        statement = `${condition.name} ${condition.comparator} :match${count}`;
        count++;
        if ('expression' in condition) statement += `${expression} `;
        break;
    }
    filterExpression += statement;
  }

  const params = {
    TableName: tableName,
    FilterExpression: filterExpression,
    ExpressionAttributeValues: attributeValues,
    Limit: limit,
  };

  return params;
};

export const createIngestProgressQuery = (id, created_at, itemData) => {
  const tableName = conf.get('dynamodb:tables:ingest-progress') || 'ingest-task';
  const timestamp = new Date().toISOString();

  const item = {
    task_uid: { S: id },
    created_at: { S: created_at },
  };

  for (const [key, value] of Object.entries(itemData)) {
    const attrType = getAttributeType(value);
    item[key] = { attrType: value };
  }

  const params = {
    TableName: tableName,
    Item: item,
  };

  return params;
};

export const deleteIngestProgressQuery = (id, created_at) => {
  const tableName = conf.get('dynamodb:tables:ingest-progress') || 'ingest-task';
  const timestamp = new Date().toISOString();

  const keyInfo = {
    task_uid: { S: id },
    created_at: { S: created_at },
  };

  const params = {
    TableName: tableName,
    Key: keyInfo,
  };

  return params;
};

export const updateIngestProgressQuery = (id, created_at, itemData) => {
  const tableName = conf.get('dynamodb:tables:ingest-progress') || 'ingest-task';
  const timestamp = new Date().toISOString();

  const keyInfo = {
    task_uid: { S: id },
    created_at: { S: created_at },
  };

  const expression = 'set ';
  const attributeValues = {};

  for (const [key, value] of Object.entries(itemData)) {
    const attrType = getAttributeType(value);
    item[key] = { attrType: value };
  }

  const params = {
    TableName: tableName,
    Key: keyInfo,
    UpdateExpression: expression,
    ExpressionAttributeValue: attributeValues,
    ReturnValues: 'ALL_NEW',
  };
};

function getAttributeType(param) {
  let attrType;

  let jsType = typeof param;
  if (jsType === 'object') {
    if (Array.isArray(param)) jsType = `${typeof param[0]}` + '-array';
  }

  return typeMap[jsType];
}
