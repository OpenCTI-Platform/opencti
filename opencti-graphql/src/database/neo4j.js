import { v1 } from 'neo4j-driver';
import conf from '../config/conf';
import DatabaseError from '../errors/DatabaseError';

const driver = v1.driver(
  conf.get('db:uri'),
  v1.auth.basic(conf.get('db:user'), conf.get('db:password')),
  { maxTransactionRetryTime: 30000 }
);

driver.onError = err => {
  throw new DatabaseError(err);
};

export default driver;
