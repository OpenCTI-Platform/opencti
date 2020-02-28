import moment from 'moment/moment';
import { head, last, mapObjIndexed, pipe, values } from 'ramda';
import { offsetToCursor } from 'graphql-relay';

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
