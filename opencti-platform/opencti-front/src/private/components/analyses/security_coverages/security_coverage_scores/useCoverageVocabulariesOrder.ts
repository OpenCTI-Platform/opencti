import { graphql, useLazyLoadQuery } from 'react-relay';
import { CoverageInformation } from '../SecurityCoverage-types';
import { useCoverageVocabulariesOrderQuery } from './__generated__/useCoverageVocabulariesOrderQuery.graphql';
import { useMemo } from 'react';

const coverageVocabulariesOrderQuery = graphql`
  query useCoverageVocabulariesOrderQuery {
    vocabularies(category: coverage_ov) {
      edges {
        node {
          order
          name
        }
      }
    }
  }
`;

export const useCoverageVocabulariesOrder = (
  coverageInformation: ReadonlyArray<CoverageInformation> | null | undefined,
): ReadonlyArray<CoverageInformation> | null | undefined => {
  const { vocabularies } = useLazyLoadQuery<useCoverageVocabulariesOrderQuery>(coverageVocabulariesOrderQuery, {});

  const DEFAULT_RANK = 0;

  const ranks = useMemo(() => new Map(
    (vocabularies?.edges ?? []).map(({ node }) => [node.name.toLowerCase(), node.order ?? DEFAULT_RANK]),
  ), [vocabularies]);

  const orderedCoverageInformation = useMemo(() => {
    return [...(coverageInformation ?? [])].sort((a, b) => {
      const rankA = ranks.get(a.coverage_name.toLowerCase()) ?? DEFAULT_RANK;
      const rankB = ranks.get(b.coverage_name.toLowerCase()) ?? DEFAULT_RANK;
      return rankA - rankB;
    });
  }, [ranks, coverageInformation]);

  return orderedCoverageInformation;
};
