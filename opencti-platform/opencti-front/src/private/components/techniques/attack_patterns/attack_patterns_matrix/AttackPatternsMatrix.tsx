import React, { FunctionComponent } from 'react';
import { TargetEntity } from '@components/common/stix_core_relationships/StixCoreRelationshipCreationFromEntity';
import {
  StixDomainObjectAttackPatternsKillChainContainer_data$data,
} from '@components/common/stix_domain_objects/__generated__/StixDomainObjectAttackPatternsKillChainContainer_data.graphql';
import { graphql } from 'react-relay';
import { AttackPatternsMatrixQuery } from '@components/techniques/attack_patterns/attack_patterns_matrix/__generated__/AttackPatternsMatrixQuery.graphql';
import Loader from '../../../../../components/Loader';
import AttackPatternsMatrixColumns from './AttackPatternsMatrixColumns';
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
  isCoverage?: boolean;
  coverageMap?: Map<string, ReadonlyArray<{ readonly coverage_name: string; readonly coverage_score: number; }>>;
  entityId?: string;
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
  isCoverage = false,
  coverageMap,
  entityId,
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
        <React.Suspense fallback={<Loader/>}>
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
            isCoverage={isCoverage}
            coverageMap={coverageMap}
            entityId={entityId}
          />
        </React.Suspense>
      )}
    </div>
  );
};

export default AttackPatternsMatrix;
