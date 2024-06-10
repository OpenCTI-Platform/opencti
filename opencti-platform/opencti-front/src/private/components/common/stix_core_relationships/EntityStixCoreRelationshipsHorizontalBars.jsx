import React from 'react';
import { graphql } from 'react-relay';
import CircularProgress from '@mui/material/CircularProgress';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import { useNavigate } from 'react-router-dom';
import makeStyles from '@mui/styles/makeStyles';
import { useTheme } from '@mui/styles';
import Chart from '../charts/Chart';
import { QueryRenderer } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import { itemColor } from '../../../../utils/Colors';
import { horizontalBarsChartOptions } from '../../../../utils/Charts';
import { simpleNumberFormat } from '../../../../utils/Number';
import { getMainRepresentative } from '../../../../utils/defaultRepresentatives';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  paper: {
    height: '100%',
    margin: '10px 0 0 0',
    padding: 0,
    borderRadius: 4,
  },
}));

const entityStixCoreRelationshipsHorizontalBarsDistributionQuery = graphql`
  query EntityStixCoreRelationshipsHorizontalBarsDistributionQuery(
    $fromId: [String]
    $toId: [String]
    $relationship_type: [String]
    $fromTypes: [String]
    $toTypes: [String]
    $field: String!
    $operation: StatsOperation!
    $limit: Int
    $startDate: DateTime
    $endDate: DateTime
    $dateAttribute: String
    $isTo: Boolean
  ) {
    stixCoreRelationshipsDistribution(
      fromId: $fromId
      toId: $toId
      relationship_type: $relationship_type
      fromTypes: $fromTypes
      toTypes: $toTypes
      field: $field
      operation: $operation
      limit: $limit
      startDate: $startDate
      endDate: $endDate
      dateAttribute: $dateAttribute
      isTo: $isTo
    ) {
      label
      value
      entity {
        ... on BasicObject {
          entity_type
        }
        ... on StixObject {
          representative {
            main
          }
        }
      }
    }
  }
`;

const EntityStixCoreRelationshipsHorizontalBars = (
  {
    fromId,
    toId,
    relationshipType,
    fromTypes,
    toTypes,
    field,
    isTo,
    startDate,
    endDate,
    dateAttribute,
    seriesName,
    title,
    variant,
  },
) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  const theme = useTheme();
  const navigate = useNavigate();

  const renderContent = () => {
    const stixCoreRelationshipsDistributionVariables = {
      relationship_type: relationshipType,
      fromId,
      toId,
      fromTypes,
      toTypes,
      field: field || 'entity_type',
      startDate: startDate || null,
      endDate: endDate || null,
      dateAttribute,
      limit: 10,
      operation: 'count',
      isTo: isTo || false,
    };
    return (
      <QueryRenderer
        query={entityStixCoreRelationshipsHorizontalBarsDistributionQuery}
        variables={stixCoreRelationshipsDistributionVariables}
        render={({ props }) => {
          if (
            props
            && props.stixCoreRelationshipsDistribution
            && props.stixCoreRelationshipsDistribution.length > 0
          ) {
            const data = props.stixCoreRelationshipsDistribution.map((n) => ({
              x:
              // eslint-disable-next-line no-nested-ternary
                field === 'internal_id'
                  ? getMainRepresentative(n.entity, t_i18n('Restricted'))
                  : field === 'entity_type'
                    ? t_i18n(`entity_${n.label}`)
                    : n.label,
              y: n.value,
              fillColor:
                field === 'internal_id'
                  ? itemColor(n.entity?.entity_type)
                  : itemColor(n.label),
            }));
            const chartData = [
              {
                name: seriesName || t_i18n('Number of relationships'),
                data,
              },
            ];
            let redirectionUtils = null;
            if (field === 'internal_id') {
              redirectionUtils = props.stixCoreRelationshipsDistribution
                .map(
                  (n) => ({
                    id: n.label,
                    name: n.entity?.representative?.main,
                    entity_type: n.entity?.entity_type,
                  }),
                );
            }
            return (
              <Chart
                options={horizontalBarsChartOptions(
                  theme,
                  true,
                  simpleNumberFormat,
                  null,
                  false,
                  navigate,
                  redirectionUtils,
                )}
                series={chartData}
                type="bar"
                width="100%"
                height="100%"
              />
            );
          }
          if (props) {
            return (
              <div style={{ display: 'table', height: '100%', width: '100%' }}>
                <span
                  style={{
                    display: 'table-cell',
                    verticalAlign: 'middle',
                    textAlign: 'center',
                  }}
                >
                  {t_i18n('No entities of this type has been found.')}
                </span>
              </div>
            );
          }
          return (
            <div style={{ display: 'table', height: '100%', width: '100%' }}>
              <span
                style={{
                  display: 'table-cell',
                  verticalAlign: 'middle',
                  textAlign: 'center',
                }}
              >
                <CircularProgress size={40} thickness={2} />
              </span>
            </div>
          );
        }}
      />
    );
  };

  return (
    <div style={{ height: '100%' }}>
      <Typography
        variant={variant === 'inEntity' ? 'h3' : 'h4'}
        gutterBottom={true}
        style={{
          margin:
          // eslint-disable-next-line no-nested-ternary
            variant === 'inEntity'
              ? 0
              : variant !== 'inLine'
                ? '0 0 10px 0'
                : '-10px 0 10px -7px',
        }}
      >
        {title || t_i18n('StixDomainObjects distribution')}
      </Typography>
      {variant === 'inLine' || variant === 'inEntity' ? (
        renderContent()
      ) : (
        <Paper classes={{ root: classes.paper }} variant="outlined">
          {renderContent()}
        </Paper>
      )}
    </div>
  );
};

export default EntityStixCoreRelationshipsHorizontalBars;
