import React, { FunctionComponent } from 'react';
import { TargetEntity } from '@components/common/stix_core_relationships/StixCoreRelationshipCreationFromEntity';
import {
  StixDomainObjectAttackPatternsKillChainContainer_data$data,
} from '@components/common/stix_domain_objects/__generated__/StixDomainObjectAttackPatternsKillChainContainer_data.graphql';
import { graphql } from 'react-relay';
import { AttackPatternsMatrixQuery } from '@components/techniques/attack_patterns/attack_patterns_matrix/__generated__/AttackPatternsMatrixQuery.graphql';
import Loader from '../../../../../components/Loader';
import AttackPatternsMatrixColumns from './AttackPatternsMatrixColumns';
import { MatrixCellEntity } from './MatrixEntityMarkers';
import { CoverageInformation } from './MatrixCoverageIndicator';
import { HeatmapScale } from './attackPatternsHeatmap';
import useQueryLoading from '../../../../../utils/hooks/useQueryLoading';

export interface AttackPatternsMatrixProps {
  attackPatterns: NonNullable<NonNullable<StixDomainObjectAttackPatternsKillChainContainer_data$data>['attackPatterns']>['edges'][0]['node'][];
  searchTerm?: string;
  handleAdd: (entity: TargetEntity) => void;
  selectedKillChain?: string;
  attackPatternIdsToOverlap?: string[];
  isModeOnlyActive: boolean;
  entityType: string;
  inPaper?: boolean;
  fillContainer?: boolean;
  // When set, only the sub-techniques that are present (covered) are kept in the
  // expandable accordion, instead of the full MITRE sub-technique list.
  onlyActiveSubAttackPatterns?: boolean;
  // attack_pattern_id -> entities (colour + shape markers) that use the technique.
  entityUsageMap?: Map<string, MatrixCellEntity[]>;
  // attack_pattern_id -> has-covered coverage scores, shown as donuts in the cell corner.
  coverageOverlayMap?: Map<string, CoverageInformation>;
  isCoverage?: boolean;
  coverageMap?: Map<string, ReadonlyArray<{ readonly coverage_name: string; readonly coverage_score: number }>>;
  entityId?: string;
  // Frequency heatmap (TTP Analyser US.3): when active, technique/sub-technique
  // cells are coloured by how many entities use them, on a relative yellow->red
  // scale. Off by default so other matrix callers are unaffected.
  heatmapActive?: boolean;
  // attack_pattern_id -> usage count (only entries with count > 0).
  frequencyMap?: Map<string, number>;
  // Relative min/max used to map counts onto the colour scale.
  heatmapScale?: HeatmapScale;
}

export const attackPatternsMatrixQuery = graphql`
  query AttackPatternsMatrixQuery {
    ...AttackPatternsMatrixColumns_data
  }
`;

const AttackPatternsMatrix: FunctionComponent<AttackPatternsMatrixProps> = ({
  attackPatterns,
  searchTerm,
  handleAdd,
  selectedKillChain,
  attackPatternIdsToOverlap,
  isModeOnlyActive,
  entityType,
  inPaper,
  fillContainer,
  onlyActiveSubAttackPatterns,
  entityUsageMap,
  coverageOverlayMap,
  isCoverage = false,
  coverageMap,
  entityId,
  heatmapActive = false,
  frequencyMap,
  heatmapScale,
}) => {
  const queryRef = useQueryLoading<AttackPatternsMatrixQuery>(attackPatternsMatrixQuery, {});

  return (
    <div style={{
      width: '100%',
      height: '100%',
      margin: 0,
      padding: 0,
    }}
    >
      {queryRef && (
        <React.Suspense fallback={<Loader />}>
          <AttackPatternsMatrixColumns
            queryRef={queryRef}
            attackPatternIdsToOverlap={attackPatternIdsToOverlap}
            attackPatterns={attackPatterns}
            entityType={entityType}
            searchTerm={searchTerm ?? ''}
            handleAdd={handleAdd}
            selectedKillChain={selectedKillChain}
            isModeOnlyActive={isModeOnlyActive}
            inPaper={inPaper}
            fillContainer={fillContainer}
            onlyActiveSubAttackPatterns={onlyActiveSubAttackPatterns}
            entityUsageMap={entityUsageMap}
            coverageOverlayMap={coverageOverlayMap}
            isCoverage={isCoverage}
            coverageMap={coverageMap}
            entityId={entityId}
            heatmapActive={heatmapActive}
            frequencyMap={frequencyMap}
            heatmapScale={heatmapScale}
          />
        </React.Suspense>
      )}
    </div>
  );
};

export default AttackPatternsMatrix;
