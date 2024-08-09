import React, { FunctionComponent } from 'react';
import { createRefetchContainer, graphql } from 'react-relay';
import { useTheme } from '@mui/material/styles';
import { Link } from 'react-router-dom';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import Checkbox from '@mui/material/Checkbox';
import ListItemText from '@mui/material/ListItemText';
import Tooltip from '@mui/material/Tooltip';
import StixCoreObjectLabels from '@components/common/stix_core_objects/StixCoreObjectLabels';
import {
  StixDomainObjectAttackPatternsKillChainContainer_data$data,
} from '@components/common/stix_domain_objects/__generated__/StixDomainObjectAttackPatternsKillChainContainer_data.graphql';
import { KeyboardArrowRightOutlined } from '@mui/icons-material';
import { AttackPatternsMatrixLine_data$data } from '@components/techniques/attack_patterns/__generated__/AttackPatternsMatrixLine_data.graphql';
import { attackPatternsLinesQuery } from './AttackPatternsLines';
import { emptyFilled, truncate } from '../../../../utils/String';
import { DataColumns } from '../../../../components/list_lines';
import ItemIcon from '../../../../components/ItemIcon';
import { HandleAddFilter } from '../../../../utils/hooks/useLocalStorage';
import ItemMarkings from '../../../../components/ItemMarkings';

export type AttackPatternNode = NonNullable<NonNullable<StixDomainObjectAttackPatternsKillChainContainer_data$data>['attackPatterns']>['edges'][0]['node'];

interface AttackPatternsMatrixLineProps {
  data: AttackPatternsMatrixLine_data$data
  dataColumns: DataColumns;
  attackPatterns: NonNullable<NonNullable<StixDomainObjectAttackPatternsKillChainContainer_data$data>['attackPatterns']>['edges'][0]['node'][];
  onLabelClick: HandleAddFilter;
  onToggleEntity: (
    entity: AttackPatternNode,
    event?: React.SyntheticEvent
  ) => void;
  onToggleShiftEntity: (
    index: number,
    entity: AttackPatternNode,
    event?: React.SyntheticEvent
  ) => void;
  selectedElements: Record<string, AttackPatternNode>;
  deSelectedElements: Record<string, AttackPatternNode>;
  selectAll: boolean;
  index: number;
}

const AttackPatternsMatrixLine: FunctionComponent<AttackPatternsMatrixLineProps> = ({
  dataColumns,
  attackPatterns,
  onLabelClick,
  onToggleEntity,
  onToggleShiftEntity,
  selectedElements,
  deSelectedElements,
  selectAll,
  index,
}) => {
  const theme = useTheme();

  return (
    <div
      style={{
        height: 'calc(100vh - 310px)',
        margin: '10px 0 -24px 0',
        overflow: 'hidden',
        whiteSpace: 'nowrap',
        paddingBottom: 20,
      }}
    >
      <div>
        {attackPatterns.map((a) => {
          const killChainNames = (a.killChainPhases || []).map((phase) => phase.kill_chain_name).join(', ');
          const phaseName = (a.killChainPhases && a.killChainPhases.length > 0) ? a.killChainPhases[0].phase_name : '';

          return (
            <ListItem
              key={a.id}
              style={{
                display: 'flex',
                flexDirection: 'row',
                alignItems: 'center',
                padding: '0 10px',
              }}
              divider={true}
              button={true}
              component={Link}
              to={`/dashboard/techniques/attack_patterns/${a.id}`}
            >
              <ListItemIcon
                style={{ color: theme.palette.primary.main, minWidth: 40 }}
                onClick={(event) => (event.shiftKey
                  ? onToggleShiftEntity(index, a, event)
                  : onToggleEntity(a, event))
                  }
              >
                <Checkbox
                  edge="start"
                  checked={
                        (selectAll && !(a.id in (deSelectedElements || {})))
                        || a.id in (selectedElements || {})
                    }
                  disableRipple={true}
                />
              </ListItemIcon>
              <ListItemIcon style={{ color: theme.palette.primary.main }}>
                <ItemIcon type="Attack-Pattern" />
              </ListItemIcon>
              <ListItemText
                primary={
                  <div
                    key={a.id}
                    style={{
                      display: 'flex',
                      flexDirection: 'row',
                      borderBottom: theme.palette.divider,
                      marginBottom: 10,
                    }}
                  >
                    <Tooltip title={`[${killChainNames}] ${phaseName}`}>
                      <div style={{ width: dataColumns.killChainPhase.width as string | number }}>
                        [{truncate(killChainNames, 15)}] {truncate(phaseName, 15)}
                      </div>
                    </Tooltip>
                    <div style={{ width: dataColumns.x_mitre_id.width as string | number }}>
                      {emptyFilled(a.x_mitre_id)}
                    </div>
                    <div style={{ width: dataColumns.name.width as string | number }}>
                      {a.name}
                    </div>
                    <div style={{ width: dataColumns.objectLabel.width as string | number }}>
                      <StixCoreObjectLabels
                        variant="inList"
                        labels={a.objectLabel}
                        onClick={onLabelClick}
                      />
                    </div>
                    <div style={{ width: dataColumns.created.width as string | number }}>
                      {a.created}
                    </div>
                    <div>
                      <ItemMarkings
                        variant="inList"
                        markingDefinitions={a.objectMarking ?? []}
                        limit={1}
                      />
                    </div>
                  </div>
                  }
              />
              <ListItemIcon style={{ position: 'absolute', right: -10 }}>
                <KeyboardArrowRightOutlined />
              </ListItemIcon>
            </ListItem>
          );
        })}
      </div>
    </div>
  );
};

export const attackPatternsMatrixLineQuery = graphql`
    query AttackPatternsMatrixLineQuery(
        $orderBy: AttackPatternsOrdering
        $orderMode: OrderingMode
        $count: Int!
        $cursor: ID
        $filters: FilterGroup
    ) {
        ...AttackPatternsMatrixLine_data
        @arguments(
            orderBy: $orderBy
            orderMode: $orderMode
            count: $count
            cursor: $cursor
            filters: $filters
        )
    }
`;

const AttackPatternsMatrixLineFragment = createRefetchContainer(
  AttackPatternsMatrixLine,
  {
    data: graphql`
            fragment AttackPatternsMatrixLine_data on Query
            @argumentDefinitions(
                orderBy: { type: "AttackPatternsOrdering", defaultValue: x_mitre_id }
                orderMode: { type: "OrderingMode", defaultValue: asc }
                count: { type: "Int", defaultValue: 25 }
                cursor: { type: "ID" }
                filters: { type: "FilterGroup" }
            ) {
                attackPatterns(
                    orderBy: $orderBy
                    orderMode: $orderMode
                    first: $count
                    after: $cursor
                    filters: $filters
                ) {
                    edges {
                        node {
                            id
                            entity_type
                            parent_types
                            name
                            description
                            isSubAttackPattern
                            x_mitre_id
                            objectMarking {
                                id
                                definition_type
                                definition
                                x_opencti_order
                                x_opencti_color
                            }
                            created
                            modified
                            objectLabel {
                                id
                                value
                                color
                            }
                            subAttackPatterns {
                                edges {
                                    node {
                                        id
                                        name
                                        description
                                        x_mitre_id
                                    }
                                }
                            }
                            killChainPhases {
                                id
                                kill_chain_name
                                phase_name
                                x_opencti_order
                            }
                            creators {
                                id
                                name
                            }
                        }
                    }
                }
            }
        `,
  },
  attackPatternsLinesQuery,
);

export default AttackPatternsMatrixLine;
