import { getKeyValue, storeKeyValue, deleteKeyValue } from '../database/redis';

export const findByKey = key => getKeyValue(key);

export const addKeyValue = input => {
  return storeKeyValue(input);
};

export const keyValueDelete = key => {
  return deleteKeyValue(key);
};
