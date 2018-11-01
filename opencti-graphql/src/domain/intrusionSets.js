import { assoc, head, isEmpty, map, pipe } from 'ramda';
import moment from 'moment';
import pubsub from '../config/bus';
import driver from '../database/neo4j';
import { FunctionalError } from '../config/errors';
import { MALWARE_ADDED_TOPIC } from '../config/conf';

export const findAll = (first, offset) => {
  const session = driver.session();
  const promise = session.run(
    'MATCH (intrusionSet:IntrusionSet) RETURN intrusionSet ORDER BY intrusionSet.id SKIP {skip} LIMIT {limit}',
    { skip: offset, limit: first }
  );
  return promise.then(data => {
    session.close();
    return map(record => record.get('intrusionSet').properties, data.records);
  });
};

export const findById = intrusionSetId => {
  const session = driver.session();
  const promise = session.run(
    'MATCH (intrusionSet:IntrusionSet {id: {intrusionSetId}}) RETURN intrusionSet',
    { intrusionSetId }
  );
  return promise.then(data => {
    session.close();
    if (isEmpty(data.records))
      throw new FunctionalError({ message: 'Cant find this intrusionSet' });
    return head(data.records).get('intrusionSet').properties;
  });
};

export const addIntrusionSet = async intrusionSet => {
  const completeIntrusionSet = pipe(
    assoc('type', 'intrusion_set'),
    assoc('created_at', moment().toISOString()),
    assoc('revoked', false)
  )(intrusionSet);
  const session = driver.session();
  const promise = session.run(
    'CREATE (intrusionSet:IntrusionSet {intrusionSet}) RETURN intrusionSet',
    { intrusionSet: completeIntrusionSet }
  );
  return promise.then(data => {
    session.close();
    const intrusionSetAdded = head(data.records).get('intrusionSet').properties;
    pubsub.publish(MALWARE_ADDED_TOPIC, { intrusionSetAdded });
    return intrusionSetAdded;
  });
};

export const deleteIntrusionSet = intrusionSetId => {
  const session = driver.session();
  const promise = session.run(
    'MATCH (intrusionSet:IntrusionSet {id: {intrusionSetId}}) DELETE intrusionSet RETURN intrusionSet',
    { intrusionSetId }
  );

  return promise.then(data => {
    session.close();
    if (isEmpty(data.records)) {
      throw new FunctionalError({ message: "IntrusionSet doesn't exist" });
    } else {
      return intrusionSetId;
    }
  });
};
