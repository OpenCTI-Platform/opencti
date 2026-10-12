import React, { FunctionComponent, useMemo } from 'react';
import { TargetEntity } from '@components/common/stix_core_relationships/StixCoreRelationshipCreationFromEntity';
import { graphql, PreloadedQuery } from 'react-relay';
import { AttackPatternsMatrixQuery } from '@components/techniques/attack_patterns/attack_patterns_matrix/__generated__/AttackPatternsMatrixQuery.graphql';
import Loader from '../../../../../components/Loader';
import AttackPatternsMatrixColumns, { AttackPatternsMatrixColumnsProps } from './AttackPatternsMatrixColumns';
import useQueryLoading from '../../../../../utils/hooks/useQueryLoading';
import { CoverageInformation } from '@components/analyses/security_coverages/SecurityCoverage-types';
import { getMatrixConfig, MatrixVariant } from './attackPatternsMatrixConfig';
import type { CellDecoration } from '@components/workspaces/investigations/matrix/matrixTypes';

export interface AttackPatternsMatrixProps {
  attackPatterns: ReadonlyArray<{ id: string }>;
  searchTerm?: string;
  handleAdd?: (entity: TargetEntity) => void;
  selectedKillChain?: string;
  attackPatternIdsToOverlap?: string[];
  isModeOnlyActive: boolean;
  entityType: string;
  inPaper?: boolean;
  isCoverage?: boolean;
  coverageMap?: Map<string, ReadonlyArray<CoverageInformation>>;
  entityId?: string;
  variant?: MatrixVariant;
  cellDecorations?: Map<string, CellDecoration>;
  queryRef?: PreloadedQuery<AttackPatternsMatrixQuery>;
  exportElementId?: string;
}

export const attackPatternsMatrixQuery = graphql`
  query AttackPatternsMatrixQuery {
    ...AttackPatternsMatrixColumns_data
  }
`;

type ColumnsWithoutQueryProps = Omit<AttackPatternsMatrixColumnsProps, 'queryRef'>;

// Used when the caller does not pass its own queryRef: loads the matrix query as before.
const AttackPatternsMatrixSelfLoading: FunctionComponent<ColumnsWithoutQueryProps> = (props) => {
  const queryRef = useQueryLoading<AttackPatternsMatrixQuery>(attackPatternsMatrixQuery, {});
  if (!queryRef) return null;
  return (
    <React.Suspense fallback={<Loader />}>
      <AttackPatternsMatrixColumns queryRef={queryRef} {...props} />
    </React.Suspense>
  );
};

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
  variant,
  cellDecorations,
  queryRef,
  exportElementId,
}) => {
  const config = useMemo(() => getMatrixConfig(variant, isCoverage), [variant, isCoverage]);

  const columnsProps: ColumnsWithoutQueryProps = {
    config,
    attackPatternIdsToOverlap,
    attackPatterns,
    entityType,
    searchTerm: searchTerm ?? '',
    handleAdd,
    selectedKillChain,
    isModeOnlyActive,
    inPaper,
    isCoverage,
    coverageMap,
    entityId,
    cellDecorations,
  };

  return (
    <div
      id={exportElementId}
      style={{
        width: '100%',
        height: '100%',
        margin: 0,
        padding: 0,
      }}
    >
      {queryRef ? (
        <React.Suspense fallback={<Loader />}>
          <AttackPatternsMatrixColumns queryRef={queryRef} {...columnsProps} />
        </React.Suspense>
      ) : (
        <AttackPatternsMatrixSelfLoading {...columnsProps} />
      )}
    </div>
  );
};

export default AttackPatternsMatrix;
