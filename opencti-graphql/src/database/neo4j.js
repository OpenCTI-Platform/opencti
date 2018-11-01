import { v1 } from 'neo4j-driver';
import conf from '../config/conf';

const driver = v1.driver(
  conf.get('db:uri'),
  v1.auth.basic(conf.get('db:user'), conf.get('db:password')),
  {
    connectionAcquisitionTimeout: 10000, // 10 sec
    maxTransactionRetryTime: 30000, // 30 sec
    disableLosslessIntegers: true
  }
);

export default driver;
