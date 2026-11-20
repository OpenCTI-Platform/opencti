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

// A list given as an array in the configuration file, or as a comma-separated string in an environment variable
export const stringListConf = (key: string) => {
  const configValue = nconf.get(key);
  const entries: unknown[] = typeof configValue === 'string' ? configValue.split(',') : (Array.isArray(configValue) ? configValue : []);
  return entries.filter((entry): entry is string => typeof entry === 'string')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
};
