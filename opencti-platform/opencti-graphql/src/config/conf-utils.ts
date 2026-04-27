import nconf from 'nconf';

/*
 * Extension of conf.js to start using TypeScript.
 */

export const stringArrayConf = (key: string) => {
  const configValue = nconf.get(key);
  if (!Array.isArray(configValue)) {
    return [];
  }
  return configValue.filter((entry): entry is string => typeof entry === 'string');
};
