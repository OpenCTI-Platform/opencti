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

// The version a build reports to XTM One: the release version of a release image, `<version>-dev.<sha7>` for a
// rolling image built from another commit (OPENCTI_BUILD_COMMIT, set by the rolling image build only), so an
// upgrade between two rolling builds of the same release is a version change. Anything but a hexadecimal commit
// keeps the release version.
export const platformBuildVersion = (version: string, commit: string | undefined) => {
  const sha = (commit ?? '').trim().toLowerCase();
  if (!/^[0-9a-f]{7,40}$/.test(sha)) {
    return version;
  }
  return `${version}-dev.${sha.slice(0, 7)}`;
};
