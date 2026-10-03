import { describe, expect, it } from 'vitest';
import { coverageVocabulariesOrder } from './SecurityCoverageScores-utils';
import { CoverageInformation } from '../SecurityCoverage-types';

describe('SecurityCoverageScores Utils', () => {
  describe('coverageVocabulariesOrder', () => {
    const score = (coverage_name: string): CoverageInformation => (
      { coverage_name, coverage_score: 50 }
    );

    interface VocabularyEdge {
      node: {
        name: string;
        order: number | null;
      };
    }

    const vocabularies = (edges: VocabularyEdge[] = []) => {
      return { edges:
    [
      {
        node: {
          order: 1,
          name: 'prevention',
        },
      },
      {
        node: {
          order: 2,
          name: 'detection',
        },
      },
      {
        node: {
          order: 3,
          name: 'vulnerability',
        },
      },
      ...edges,
    ],
      };
    };

    describe('When receiving orders for default vocabularies values', () => {
      it('should sort coverage information following the vocabulary order', () => {
        const orderedCoverageInformation = coverageVocabulariesOrder(
          [
            score('vulnerability'),
            score('prevention'),
            score('detection'),
          ],
          vocabularies());

        const expectedResult = [
          {
            coverage_name: 'prevention',
            coverage_score: 50,
          },
          {
            coverage_name: 'detection',
            coverage_score: 50,
          },
          {
            coverage_name: 'vulnerability',
            coverage_score: 50,
          },
        ];

        expect(orderedCoverageInformation).toEqual(expectedResult);
      });

      it('should sort regardless of the case used in coverage_name', () => {
        const orderedCoverageInformation = coverageVocabulariesOrder(
          [
            score('VULNERABILITY'),
            score('Detection'),
            score('prevention'),
          ],
          vocabularies());

        const expectedResult = [
          {
            coverage_name: 'prevention',
            coverage_score: 50,
          },
          {
            coverage_name: 'Detection',
            coverage_score: 50,
          },
          {
            coverage_name: 'VULNERABILITY',
            coverage_score: 50,
          },
        ];

        expect(orderedCoverageInformation).toEqual(expectedResult);
      });

      it('should sort a partial list of coverage information', () => {
        const orderedCoverageInformation = coverageVocabulariesOrder(
          [
            score('vulnerability'),
            score('prevention'),
          ],
          vocabularies());

        const expectedResult = [
          {
            coverage_name: 'prevention',
            coverage_score: 50,
          },
          {
            coverage_name: 'vulnerability',
            coverage_score: 50,
          },
        ];

        expect(orderedCoverageInformation).toEqual(expectedResult);
      });

      it('should return an empty array when there is no coverage information', () => {
        expect(coverageVocabulariesOrder(null, vocabularies())).toEqual([]);
        expect(coverageVocabulariesOrder(undefined, vocabularies())).toEqual([]);
        expect(coverageVocabulariesOrder([], vocabularies())).toEqual([]);
      });
    });

    describe('When receiving custom vocabularies with no order', () => {
      const additionnalNodesWithoutOrder = [{
        node: {
          name: 'manual',
          order: null,
        },
      },
      {
        node: {
          name: 'resilience',
          order: null,
        },
      }];

      it('should put a custom vocabulary without order before the default ones', () => {
        const orderedCoverageInformation = coverageVocabulariesOrder(
          [
            score('detection'),
            score('manual'),
            score('prevention'),
          ],
          vocabularies(additionnalNodesWithoutOrder),
        );

        const expectedResult = [
          {
            coverage_name: 'manual',
            coverage_score: 50,
          },
          {
            coverage_name: 'prevention',
            coverage_score: 50,
          },
          {
            coverage_name: 'detection',
            coverage_score: 50,
          },
        ];

        expect(orderedCoverageInformation).toEqual(expectedResult);
      });

      it('should put a coverage_name missing from the vocabulary before the default ones', () => {
        const orderedCoverageInformation = coverageVocabulariesOrder(
          [
            score('detection'),
            score('unknown-from-vocabulary'),
            score('prevention'),
          ],
          vocabularies(additionnalNodesWithoutOrder));

        const expectedResult = [
          {
            coverage_name: 'unknown-from-vocabulary',
            coverage_score: 50,
          },
          {
            coverage_name: 'prevention',
            coverage_score: 50,
          },
          {
            coverage_name: 'detection',
            coverage_score: 50,
          },
        ];

        expect(orderedCoverageInformation).toEqual(expectedResult);
      });
    });

    describe('When receiving custom vocabularies with order', () => {
      const additionnalNodesWithOrder = [
        {
          node: {
            name: 'hardening',
            order: 0,
          },
        },
        {
          node: {
            name: 'baseline',
            order: 5,
          },
        },
        {
          node: {
            name: 'response',
            order: 2,
          },
        },
      ];

      it('should correctly order custom and default vocabularies', () => {
        const orderedCoverageInformation = coverageVocabulariesOrder(
          [
            score('vulnerability'),
            score('hardening'),
            score('baseline'),
            score('prevention'),
            score('detection'),
            score('response'),
          ],
          vocabularies(additionnalNodesWithOrder));

        const expectedResult = [
          {
            coverage_name: 'hardening',
            coverage_score: 50,
          },
          {
            coverage_name: 'prevention',
            coverage_score: 50,
          },
          {
            coverage_name: 'detection',
            coverage_score: 50,
          },
          {
            coverage_name: 'response',
            coverage_score: 50,
          },
          {
            coverage_name: 'vulnerability',
            coverage_score: 50,
          },
          {
            coverage_name: 'baseline',
            coverage_score: 50,
          },
        ];

        expect(orderedCoverageInformation).toEqual(expectedResult);
      });
    });
  });
});
