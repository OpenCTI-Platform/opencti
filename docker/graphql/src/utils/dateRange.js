import moment from 'moment';

/**
 * Return date range object for mongo find query
 * @param {Object} query Koa querystring object from ctx.request
 * @return {Object} Mongo compatible date range query object
 */

export default query => {
  let start;
  let end;
  // If the number is more than 5 digits long, it's likely unix
  if (/\d{5,}/.test(query.start && (query.final || query.end))) {
    start = moment.utc(query.start * 1000);
    end = moment.utc(query.final * 1000 || query.end * 1000);
  } else {
    start = moment.utc(query.start);
    end = moment.utc(query.final || query.end);
  }

  return { $gte: start.toISOString(), $lte: end.toISOString() };
};
