import { ENTITY_TYPE_CONNECTOR, ENTITY_TYPE_USER } from '../../src/schema/internalObject';
import { TESTING_USERS } from './testQuery';

const testCreateCounter: Record<string, number> = {};
const testDeleteCounter: Record<string, number> = {};

/**
 * This should init with all data in database after running 'yarn test:dev:init'
 * or else 'yarn test:dev:resume' will not work.
 * It includes testQuery data (so do not use addCreateInCounter in testQuery).
 */
export const initTestCounters = () => {
  testCreateCounter[ENTITY_TYPE_CONNECTOR] = 2;
  testCreateCounter[ENTITY_TYPE_USER] = TESTING_USERS.length + 1;
};

export const addCreateInCounter = (name: string) => {
  const currentCount = testCreateCounter[name];
  let finalCount = 1;
  if (currentCount) {
    finalCount = currentCount + 1;
  }
  testCreateCounter[name] = finalCount;
};

export const addDeleteInCounter = (name: string) => {
  const currentCount = testDeleteCounter[name];
  let finalCount = 1;
  if (currentCount) {
    finalCount = currentCount + 1;
  }
  testDeleteCounter[name] = finalCount;
};

export const getCounterTotal = (name: string) => {
  const created = testCreateCounter[name] ?? 0;
  const deleted = testDeleteCounter[name] ?? 0;
  const total = created - deleted;
  return total;
};
