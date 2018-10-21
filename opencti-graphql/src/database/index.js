import { v1 } from 'neo4j-driver';
import conf from '../config/conf';

const driver = v1.driver(
  conf.get('db:uri'),
  v1.auth.basic(conf.get('db:user'), conf.get('db:password')),
  { maxTransactionRetryTime: 30000 }
);

export default driver;
