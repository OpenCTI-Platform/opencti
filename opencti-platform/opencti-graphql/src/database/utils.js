import moment from 'moment/moment';
import { head, last, mapObjIndexed, pipe, values } from 'ramda';
import { offsetToCursor } from 'graphql-relay';
import { PythonShell } from 'python-shell';
import { logger } from '../config/conf';

export const fillTimeSeries = (startDate, endDate, interval, data) => {
  const startDateParsed = moment(startDate);
  const endDateParsed = moment(endDate);
  let dateFormat;

  switch (interval) {
    case 'year':
      dateFormat = 'YYYY';
      break;
    case 'month':
      dateFormat = 'YYYY-MM';
      break;
    default:
      dateFormat = 'YYYY-MM-DD';
  }

  const elementsOfInterval = endDateParsed.diff(startDateParsed, `${interval}s`, false);

  const newData = [];
  for (let i = 0; i <= elementsOfInterval; i += 1) {
    let dataValue = 0;
    for (let j = 0; j < data.length; j += 1) {
      if (data[j].date === startDateParsed.format(dateFormat)) {
        dataValue = data[j].value;
      }
    }
    newData[i] = {
      date: startDateParsed.startOf(interval).format(),
      value: dataValue
    };
    startDateParsed.add(1, `${interval}s`);
  }
  return newData;
};

/**
 * Pure building of pagination expected format.
 * @param first
 * @param offset
 * @param instances
 * @param globalCount
 * @returns {{edges: *, pageInfo: *}}
 */
export const buildPagination = (first, offset, instances, globalCount) => {
  const edges = pipe(
    mapObjIndexed((record, key) => {
      const { node } = record;
      const { relation } = record;
      const nodeOffset = offset + parseInt(key, 10) + 1;
      return { node, relation, cursor: offsetToCursor(nodeOffset) };
    }),
    values
  )(instances);
  const hasNextPage = first + offset < globalCount;
  const hasPreviousPage = offset > 0;
  const startCursor = edges.length > 0 ? head(edges).cursor : '';
  const endCursor = edges.length > 0 ? last(edges).cursor : '';
  const pageInfo = {
    startCursor,
    endCursor,
    hasNextPage,
    hasPreviousPage,
    globalCount
  };
  return { edges, pageInfo };
};

export const execPython3 = async (scriptPath, scriptName, args) => {
  try {
    return new Promise((resolve, reject) => {
      const options = {
        mode: 'text',
        pythonPath: 'python3',
        scriptPath,
        args
      };
      return PythonShell.run(scriptName, options, (err, results) => {
        if (err) {
          reject(new Error(`Python3 is missing or script not found: ${err}`));
        }
        try {
          let result = results[0];
          if (result.includes('ANTLR')) {
            // eslint-disable-next-line prefer-destructuring
            result = results[2];
          }
          result = JSON.parse(result);
          resolve(result);
        } catch (err2) {
          reject(new Error(`No valid JSON from Python script: ${err2}`));
        }
      });
    });
  } catch (err) {
    throw new Error(`Python3 is missing or script not found: ${err}`);
  }
};

export const checkPythonStix2 = async () => {
  try {
    const result = await execPython3('./src/utils/stix2', 'stix2_create_pattern.py', ['check', 'health']);
    if (result.status !== 'success') {
      throw new Error('Python3 with STIX2 module is missing');
    }
  } catch (err) {
    throw new Error('Python3 with STIX2 module is missing');
  }
};

export const createStixPattern = async (observableType, observableValue) => {
  try {
    const result = await execPython3('./src/utils/stix2', 'stix2_create_pattern.py', [observableType, observableValue]);
    if (result.status === 'success') {
      return result.data;
    }
    return null;
  } catch (err) {
    logger.error('[Python3] createStixPattern error > ', err);
    return null;
  }
};

export const extractObservables = async pattern => {
  try {
    const result = await execPython3('./src/utils/stix2', 'stix2_extract_observables.py', [pattern]);
    if (result.status === 'success') {
      return result.data;
    }
    return null;
  } catch (err) {
    logger.error('[Python3] extractObservables error > ', err);
    return null;
  }
};
