import { CoverageInformation } from '../SecurityCoverage-types';
import { SecurityCoverageScoresVocabulariesOrderQuery$data } from './__generated__/SecurityCoverageScoresVocabulariesOrderQuery.graphql';

export const coverageVocabulariesOrder = (
  coverageInformation: ReadonlyArray<CoverageInformation> | null | undefined,
  vocabularies: SecurityCoverageScoresVocabulariesOrderQuery$data['vocabularies'],
): ReadonlyArray<CoverageInformation> | null | undefined => {
  const DEFAULT_RANK = 0;

  const ranks = new Map(
    (vocabularies?.edges ?? []).map(({ node }) => [node.name.toLowerCase(), node.order ?? DEFAULT_RANK]));

  const orderedCoverageInformation = [...(coverageInformation ?? [])].sort((a, b) => {
    const rankA = ranks.get(a.coverage_name.toLowerCase()) ?? DEFAULT_RANK;
    const rankB = ranks.get(b.coverage_name.toLowerCase()) ?? DEFAULT_RANK;
    return rankA - rankB;
  });

  return orderedCoverageInformation;
};
