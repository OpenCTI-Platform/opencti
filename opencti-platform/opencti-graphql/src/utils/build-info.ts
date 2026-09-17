const GIT_REVISION_PATTERN = /^[0-9a-f]{7,}$/i;

export const normalizeBuildCommit = (value: string | undefined): string | undefined => {
  const trimmedValue = value?.trim();
  if (!trimmedValue || !GIT_REVISION_PATTERN.test(trimmedValue)) {
    return undefined;
  }
  return trimmedValue.slice(0, 7);
};

export const getBuildCommit = (): string | undefined => normalizeBuildCommit(process.env.BUILD_COMMIT);
