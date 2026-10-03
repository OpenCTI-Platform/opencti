import type { CoverageInformation } from '../securityCoverage/securityCoverageResult/securityCoverageResult-types';

// Coverage entry written by the platform from hunt runs triggered by OpenAEV emulations (coverage_ov vocabulary key)
export const HUNT_DETECTED_COVERAGE = 'hunt_detected';
// Coverage entries owned by the platform: they survive a full replacement of coverage_information by an integration
export const PLATFORM_OWNED_COVERAGE_NAMES = [HUNT_DETECTED_COVERAGE];

/**
 * coverage_information is replaced as a whole by integrations upserts (OpenAEV results):
 * the entries computed by the platform are kept when the incoming value does not carry them.
 */
export const preservePlatformCoverage = (current: CoverageInformation[] | null | undefined, incoming: CoverageInformation[] | null | undefined) => {
  const incomingValues = incoming ?? [];
  const incomingNames = new Set(incomingValues.map((entry) => entry.coverage_name));
  const preserved = (current ?? []).filter((entry) => PLATFORM_OWNED_COVERAGE_NAMES.includes(entry.coverage_name) && !incomingNames.has(entry.coverage_name));
  return [...incomingValues, ...preserved];
};

export const mergeHuntDetectedCoverage = (current: CoverageInformation[] | null | undefined, detected: boolean): CoverageInformation[] => {
  return [
    ...(current ?? []).filter((entry) => entry.coverage_name !== HUNT_DETECTED_COVERAGE),
    { coverage_name: HUNT_DETECTED_COVERAGE, coverage_score: detected ? 100 : 0 },
  ];
};
