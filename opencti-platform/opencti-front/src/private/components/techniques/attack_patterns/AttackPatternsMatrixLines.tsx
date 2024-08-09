import React, { FunctionComponent } from 'react';
import {
  StixDomainObjectAttackPatternsKillChainContainer_data$data,
} from '@components/common/stix_domain_objects/__generated__/StixDomainObjectAttackPatternsKillChainContainer_data.graphql';
import AttackPatternsMatrixLine, { AttackPatternNode, attackPatternsMatrixLineQuery } from '@components/techniques/attack_patterns/AttackPatternsMatrixLine';
import { AttackPatternsMatrixLine_data$data } from '@components/techniques/attack_patterns/__generated__/AttackPatternsMatrixLine_data.graphql';
import { QueryRenderer } from '../../../../relay/environment';
import Loader from '../../../../components/Loader';
import { DataColumns } from '../../../../components/list_lines';
import { UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';

const nbOfRowsToLoad = 50;

interface AttackPatternsMatrixLinesProps {
  attackPatterns: NonNullable<NonNullable<StixDomainObjectAttackPatternsKillChainContainer_data$data>['attackPatterns']>['edges'][0]['node'][];
  dataColumns: DataColumns;
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
  selectedElements: Record<string, AttackPatternNode>;
  deSelectedElements: Record<string, AttackPatternNode>;
  onToggleEntity: (
    entity: AttackPatternNode,
    event: React.SyntheticEvent
  ) => void;
  onToggleShiftEntity: (
    index: number,
    entity: AttackPatternNode,
    event?: React.SyntheticEvent
  ) => void;
  selectAll: boolean;
}
const AttackPatternsMatrixLines: FunctionComponent<AttackPatternsMatrixLinesProps> = ({
  attackPatterns,
  dataColumns,
  onToggleEntity,
  onToggleShiftEntity,
  selectedElements,
  deSelectedElements,
  selectAll,
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
        query={attackPatternsMatrixLineQuery}
        variables={{
          count: 5000,
          filters: {
            mode: 'and',
            filters: [{ key: 'revoked', values: ['false'] }],
            filterGroups: [],
          },
        }}
        render={({ props }: { props: AttackPatternsMatrixLine_data$data | null }) => {
          if (props) {
            return (
              <AttackPatternsMatrixLine
                data={props}
                dataColumns={dataColumns}
                attackPatterns={attackPatterns}
                nbOfRowsToLoad={nbOfRowsToLoad}
                selectedElements={selectedElements}
                deSelectedElements={deSelectedElements}
                selectAll={selectAll}
                onToggleEntity={onToggleEntity}
                onToggleShiftEntity={onToggleShiftEntity}
              />
            );
          }
          return <Loader />;
        }}
      />
    </div>
  );
};

export default AttackPatternsMatrixLines;
