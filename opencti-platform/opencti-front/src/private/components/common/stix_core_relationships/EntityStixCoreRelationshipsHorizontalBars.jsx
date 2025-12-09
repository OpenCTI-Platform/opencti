import { graphql } from 'react-relay';
import CircularProgress from '@mui/material/CircularProgress';
import { useNavigate } from 'react-router-dom';
import { useTheme } from '@mui/styles';
import Card from '@common/card/Card';
import Chart from '../charts/Chart';
import { QueryRenderer } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import { itemColor } from '../../../../utils/Colors';
import { horizontalBarsChartOptions } from '../../../../utils/Charts';
import { simpleNumberFormat } from '../../../../utils/Number';
import { getMainRepresentative } from '../../../../utils/defaultRepresentatives';
import { NO_DATA_WIDGET_MESSAGE } from '../../../../components/dashboard/WidgetNoData';

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
  },
) => {
  const { t_i18n } = useFormatter();
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
                  {t_i18n(NO_DATA_WIDGET_MESSAGE)}
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
    <Card title={title || t_i18n('StixDomainObjects distribution')}>
      {renderContent()}
    </Card>
  );
};

export default EntityStixCoreRelationshipsHorizontalBars;
