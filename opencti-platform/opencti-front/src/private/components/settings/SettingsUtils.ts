export const formatOpenCTIVersion = (version: string, buildCommit?: string | null): string => {
  return buildCommit ? `${version} (${buildCommit})` : version;
};
