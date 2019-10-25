import { getKeyValue, storeKeyValue, deleteKeyValue } from '../database/redis';

export const findByKey = key => getKeyValue(key);

export const addKeyValue = input => {
  return storeKeyValue(input.key, input.value);
};

export const keyValueDelete = key => {
  return deleteKeyValue(key);
};

export const keyValueUpdate = (key, value) => {
  return storeKeyValue(key, value);
};
