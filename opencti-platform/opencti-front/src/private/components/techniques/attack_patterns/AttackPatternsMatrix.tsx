import React, { FunctionComponent } from 'react';
import { TargetEntity } from '@components/common/stix_core_relationships/StixCoreRelationshipCreationFromEntity';
import {
  StixDomainObjectAttackPatternsKillChainContainer_data$data,
} from '@components/common/stix_domain_objects/__generated__/StixDomainObjectAttackPatternsKillChainContainer_data.graphql';
import { QueryRenderer } from '../../../../relay/environment';
import Loader from '../../../../components/Loader';
import AttackPatternsMatrixColumns, { attackPatternsMatrixColumnsQuery } from './AttackPatternsMatrixColumns';
import { AttackPatternsMatrixColumnsQuery } from './__generated__/AttackPatternsMatrixColumnsQuery.graphql';

interface AttackPatternsMatrixProps {
  marginRight?: boolean;
  attackPatterns: NonNullable<NonNullable<StixDomainObjectAttackPatternsKillChainContainer_data$data>['attackPatterns']>['edges'][0]['node'][];
  searchTerm?: string;
  handleToggleColorsReversed: () => void;
  currentColorsReversed: boolean;
  hideBar: boolean;
  handleAdd: (entity: TargetEntity) => void;
}
const AttackPatternsMatrix: FunctionComponent<AttackPatternsMatrixProps> = ({
  attackPatterns,
  marginRight,
  searchTerm,
  handleToggleColorsReversed,
  currentColorsReversed,
  hideBar,
  handleAdd,
}) => {
  return (
    <div style={{
      width: '100%',
      height: '100%',
      margin: 0,
      padding: 0,
    }}
    >
      <QueryRenderer
        query={attackPatternsMatrixColumnsQuery}
        variables={{
          count: 5000,
          filters: {
            mode: 'and',
            filters: [{ key: 'revoked', values: ['false'] }],
            filterGroups: [],
          },
        }}
        render={({ props }: { props: AttackPatternsMatrixColumnsQuery | null }) => {
          if (props) {
            return (
              <AttackPatternsMatrixColumns
                data={props}
                attackPatterns={attackPatterns}
                marginRight={marginRight}
                searchTerm={searchTerm ?? ''}
                handleToggleColorsReversed={handleToggleColorsReversed}
                currentColorsReversed={currentColorsReversed}
                hideBar={hideBar}
                handleAdd={handleAdd}
              />
            );
          }
          return <Loader />;
        }}
      />
    </div>
  );
};

export default AttackPatternsMatrix;
