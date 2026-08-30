import React from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql } from 'react-relay';
import withTheme from '@mui/styles/withTheme';
import withStyles from '@mui/styles/withStyles';
import CircularProgress from '@mui/material/CircularProgress';
import * as R from 'ramda';
import Chart from '../../common/charts/Chart';
import { QueryRenderer } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import { donutChartOptions } from '../../../../utils/Charts';
import { getMainRepresentative } from '../../../../utils/defaultRepresentatives';
import { NO_DATA_WIDGET_MESSAGE } from '../../../../components/dashboard/WidgetNoData';
import Card from '../../../../components/common/card/Card';

const styles = (theme) => ({
  paper: {
    height: '100%',
    marginTop: theme.spacing(1),
    borderRadius: 4,
  },
  updateButton: {
    float: 'right',
    margin: '7px 10px 0 0',
  },
});

const entityStixSightingRelationshipsDonutStixSightingRelationshipsDistributionQuery = graphql`
  query EntityStixSightingRelationshipsDonutStixSightingRelationshipsDistributionQuery(
    $fromId: StixRef!
    $limit: Int
    $startDate: DateTime
    $endDate: DateTime
    $field: String!
    $operation: StatsOperation!
  ) {
    stixSightingRelationshipsDistribution(
      fromId: $fromId
      limit: $limit
      startDate: $startDate
      endDate: $endDate
      field: $field
      operation: $operation
    ) {
      label
      value
      entity {
        ... on BasicObject {
          entity_type
        }
        ... on AttackPattern {
          name
          description
        }
        ... on Campaign {
          name
          description
        }
        ... on CourseOfAction {
          name
          description
        }
        ... on Individual {
          name
          description
        }
        ... on Organization {
          name
          description
        }
        ... on Sector {
          name
          description
        }
        ... on System {
          name
          description
        }
        ... on Indicator {
          name
          description
        }
        ... on Infrastructure {
          name
          description
        }
        ... on IntrusionSet {
          name
          description
        }
        ... on Position {
          name
          description
        }
        ... on City {
          name
          description
        }
        ... on AdministrativeArea {
          name
          description
        }
        ... on Country {
          name
          description
        }
        ... on Region {
          name
          description
        }
        ... on Malware {
          name
          description
        }
        ... on ThreatActor {
          name
          description
        }
        ... on Tool {
          name
          description
        }
        ... on Vulnerability {
          name
          description
        }
        ... on Incident {
          name
          description
        }
      }
    }
  }
`;

const EntityStixSightingRelationshipsDonut = (props) => {
  const { t_i18n } = useFormatter();

  const renderContent = () => {
    const { entityId, variant, field, startDate, endDate, theme, toTypes } = props;
    const stixSightingRelationshipsDistributionVariables = {
      fromId: entityId,
      startDate: startDate || null,
      endDate: endDate || null,
      field,
      limit: 10,
      operation: 'count',
    };
    return (
      <QueryRenderer
        query={
          entityStixSightingRelationshipsDonutStixSightingRelationshipsDistributionQuery
        }
        variables={stixSightingRelationshipsDistributionVariables}
        render={({ props }) => {
          if (
            props
            && props.stixSightingRelationshipsDistribution
            && props.stixSightingRelationshipsDistribution.length > 0
          ) {
            let data = props.stixSightingRelationshipsDistribution;
            if (field === 'internal_id') {
              data = R.map(
                (n) => R.assoc(
                  'label',
                  `${
                    toTypes.length > 1 && n.entity
                      ? `[${t_i18n(`entity_${n.entity.entity_type}`)}] ${n.entity.name}`
                      : `${getMainRepresentative(n.entity) || n.label}`
                  }`,
                  n,
                ),
                props.stixSightingRelationshipsDistribution,
              );
            }
            const chartData = data.map((n) => n.value);
            const labels = data.map((n) => (field === 'entity_type' ? t_i18n(`entity_${n.label}`) : n.label));
            return (
              <Chart
                options={donutChartOptions(
                  theme,
                  labels,
                  variant === 'inEntity' ? 'left' : 'right',
                )}
                series={chartData}
                type="donut"
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

  const { title } = props;
  return (
    <Card title={title || t_i18n('Distribution of entities')}>
      {renderContent()}
    </Card>
  );
};

EntityStixSightingRelationshipsDonut.propTypes = {
  title: PropTypes.string,
  entityId: PropTypes.string,
  entityType: PropTypes.string,
  startDate: PropTypes.string,
  endDate: PropTypes.string,
  field: PropTypes.string,
  classes: PropTypes.object,
  theme: PropTypes.object,
  toTypes: PropTypes.array,
};

export default compose(
  withTheme,
  withStyles(styles),
)(EntityStixSightingRelationshipsDonut);
