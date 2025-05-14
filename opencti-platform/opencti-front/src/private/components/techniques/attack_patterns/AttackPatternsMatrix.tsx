import React, { FunctionComponent } from 'react';
import { TargetEntity } from '@components/common/stix_core_relationships/StixCoreRelationshipCreationFromEntity';
import {
  StixDomainObjectAttackPatternsKillChainContainer_data$data,
} from '@components/common/stix_domain_objects/__generated__/StixDomainObjectAttackPatternsKillChainContainer_data.graphql';
import Loader from '../../../../components/Loader';
import AttackPatternsMatrixColumns, { attackPatternsMatrixColumnsQuery } from './AttackPatternsMatrixColumns';
import { AttackPatternsMatrixColumnsQuery } from './__generated__/AttackPatternsMatrixColumnsQuery.graphql';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';

export interface AttackPatternsMatrixProps {
  marginRight?: boolean;
  attackPatterns: NonNullable<NonNullable<StixDomainObjectAttackPatternsKillChainContainer_data$data>['attackPatterns']>['edges'][0]['node'][];
  searchTerm?: string;
  handleToggleColorsReversed: () => void;
  currentColorsReversed: boolean;
  handleAdd: (entity: TargetEntity) => void;
  selectedKillChain?: string;
  noBottomBar?: boolean;
}
const AttackPatternsMatrix: FunctionComponent<AttackPatternsMatrixProps> = ({
  attackPatterns,
  marginRight,
  searchTerm,
  handleToggleColorsReversed,
  currentColorsReversed,
  handleAdd,
  selectedKillChain,
  noBottomBar,
}) => {
  const queryRef = useQueryLoading<AttackPatternsMatrixColumnsQuery>(attackPatternsMatrixColumnsQuery, {});

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
            attackPatterns={attackPatterns}
            marginRight={marginRight}
            searchTerm={searchTerm ?? ''}
            handleToggleColorsReversed={handleToggleColorsReversed}
            currentColorsReversed={currentColorsReversed}
            handleAdd={handleAdd}
            selectedKillChain={selectedKillChain}
            noBottomBar={noBottomBar}
          />
        </React.Suspense>
      )}
    </div>
  );
};

export default AttackPatternsMatrix;
