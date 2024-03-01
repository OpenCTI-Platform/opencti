import semver from 'semver';

export const isCompatibleVersionWithMinimal = (version: string, minimalVersion: string) => {
  return semver.gte(version, minimalVersion);
};
