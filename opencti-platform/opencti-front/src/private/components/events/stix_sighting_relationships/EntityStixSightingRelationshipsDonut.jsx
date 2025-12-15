import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql } from 'react-relay';
import withTheme from '@mui/styles/withTheme';
import withStyles from '@mui/styles/withStyles';
import CircularProgress from '@mui/material/CircularProgress';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import * as R from 'ramda';
import Chart from '../../common/charts/Chart';
import { QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import { donutChartOptions } from '../../../../utils/Charts';
import { getMainRepresentative } from '../../../../utils/defaultRepresentatives';
import { NO_DATA_WIDGET_MESSAGE } from '../../../../components/dashboard/WidgetNoData';

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

class EntityStixSightingRelationshipsDonut extends Component {
  constructor(props) {
    super(props);
    this.renderLabel = this.renderLabel.bind(this);
    this.renderSimpleLabel = this.renderSimpleLabel.bind(this);
  }

  renderSimpleLabel(props) {
    return props.value;
  }

  renderLabel(props) {
    const { theme } = this.props;
    const RADIAN = Math.PI / 180;
    const { cx, cy, midAngle, outerRadius, fill, payload, percent, value } = props;
    const sin = Math.sin(-RADIAN * midAngle);
    const cos = Math.cos(-RADIAN * midAngle);
    const sx = cx + (outerRadius + 10) * cos;
    const sy = cy + (outerRadius + 10) * sin;
    const mx = cx + (outerRadius + 30) * cos;
    const my = cy + (outerRadius + 30) * sin;
    const ex = mx + (cos >= 0 ? 1 : -1) * 22;
    const ey = my;
    const textAnchor = cos >= 0 ? 'start' : 'end';

    return (
      <g>
        <path
          d={`M${sx},${sy}L${mx},${my}L${ex},${ey}`}
          stroke={fill}
          fill="none"
        />
        <circle cx={ex} cy={ey} r={2} fill={fill} stroke="none" />
        <text
          x={ex + (cos >= 0 ? 1 : -1) * 12}
          y={ey}
          textAnchor={textAnchor}
          fill={theme.palette.text.primary}
          style={{ fontSize: 12 }}
        >
          {' '}
          {payload.label} ({value})
        </text>
        <text
          x={ex + (cos >= 0 ? 1 : -1) * 12}
          y={ey}
          dy={18}
          textAnchor={textAnchor}
          fill="#999999"
          style={{ fontSize: 12 }}
        >
          {` ${(percent * 100).toFixed(2)}%`}
        </text>
      </g>
    );
  }

  renderContent() {
    const { t, entityId, variant, field, startDate, endDate, theme, toTypes } = this.props;
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
                      ? `[${t(`entity_${n.entity.entity_type}`)}] ${n.entity.name}`
                      : `${getMainRepresentative(n.entity) || n.label}`
                  }`,
                  n,
                ),
                props.stixSightingRelationshipsDistribution,
              );
            }
            const chartData = data.map((n) => n.value);
            const labels = data.map((n) => (field === 'entity_type' ? t(`entity_${n.label}`) : n.label));
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
                  {t(NO_DATA_WIDGET_MESSAGE)}
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
  }

  render() {
    const { t, classes, title, variant, height } = this.props;
    return (
      <div style={{ height: height || '100%' }}>
        <Typography
          variant={variant === 'inEntity' ? 'h3' : 'h4'}
          gutterBottom={true}
        >
          {title || t('Distribution of entities')}
        </Typography>
        {variant === 'inLine' || variant === 'inEntity' ? (
          this.renderContent()
        ) : (
          <Paper classes={{ root: classes.paper }} variant="outlined">
            {this.renderContent()}
          </Paper>
        )}
      </div>
    );
  }
}

EntityStixSightingRelationshipsDonut.propTypes = {
  title: PropTypes.string,
  variant: PropTypes.string,
  entityId: PropTypes.string,
  entityType: PropTypes.string,
  startDate: PropTypes.string,
  endDate: PropTypes.string,
  field: PropTypes.string,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
  toTypes: PropTypes.array,
};

export default compose(
  inject18n,
  withTheme,
  withStyles(styles),
)(EntityStixSightingRelationshipsDonut);
