import React, { FunctionComponent } from 'react';
import { TargetEntity } from '@components/common/stix_core_relationships/StixCoreRelationshipCreationFromEntity';
import {
  StixDomainObjectAttackPatternsKillChainContainer_data$data,
} from '@components/common/stix_domain_objects/__generated__/StixDomainObjectAttackPatternsKillChainContainer_data.graphql';
import { graphql } from 'react-relay';
import Loader from '../../../../components/Loader';
import AttackPatternsMatrixColumns from './AttackPatternsMatrixColumns';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { AttackPatternsMatrixQuery } from './__generated__/AttackPatternsMatrixQuery.graphql';

export interface AttackPatternsMatrixProps {
  marginRight?: boolean;
  attackPatterns: NonNullable<NonNullable<StixDomainObjectAttackPatternsKillChainContainer_data$data>['attackPatterns']>['edges'][0]['node'][];
  searchTerm?: string;
  handleAdd: (entity: TargetEntity) => void;
  selectedKillChain?: string;
}

export const attackPatternsMatrixQuery = graphql`
  query AttackPatternsMatrixQuery {
    ...AttackPatternsMatrixColumns_data
  }
`;

const AttackPatternsMatrix: FunctionComponent<AttackPatternsMatrixProps> = ({
  attackPatterns,
  marginRight,
  searchTerm,
  handleAdd,
  selectedKillChain,
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
            attackPatterns={attackPatterns}
            marginRight={marginRight}
            searchTerm={searchTerm ?? ''}
            handleAdd={handleAdd}
            selectedKillChain={selectedKillChain}
          />
        </React.Suspense>
      )}
    </div>
  );
};

export default AttackPatternsMatrix;
