import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { assoc, compose, map } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import {
  ResponsiveContainer, PieChart, Pie, Cell, Legend,
} from 'recharts';
import { withStyles } from '@material-ui/core/styles';
import CircularProgress from '@material-ui/core/CircularProgress';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import { QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import { itemColor } from '../../../../utils/Colors';

const styles = () => ({
  paper: {
    height: '100%',
    margin: '10px 0 0 0',
    borderRadius: 6,
  },
  updateButton: {
    float: 'right',
    margin: '7px 10px 0 0',
  },
});

const entityStixSightingRelationshipsDonutStixSightingRelationshipsDistributionQuery = graphql`
  query EntityStixSightingRelationshipsDonutStixSightingRelationshipsDistributionQuery(
    $fromId: String!
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

  // eslint-disable-next-line class-methods-use-this
  renderSimpleLabel(props) {
    return props.value;
  }

  // eslint-disable-next-line class-methods-use-this
  renderLabel(props) {
    const RADIAN = Math.PI / 180;
    const {
      cx,
      cy,
      midAngle,
      outerRadius,
      fill,
      payload,
      percent,
      value,
    } = props;
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
          fill="#ffffff"
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
    const {
      t, entityId, variant, field, startDate, endDate,
    } = this.props;
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
              data = map(
                (n) => assoc('label', n.entity.name, n),
                props.stixSightingRelationshipsDistribution,
              );
            }
            return (
              <ResponsiveContainer height="100%" width="100%">
                <PieChart
                  margin={{
                    top:
                      variant === 'inEntity' || variant === 'inKnowledge'
                        ? 40
                        : 0,
                    right: 0,
                    bottom:
                      // eslint-disable-next-line no-nested-ternary
                      variant === 'inLine'
                        ? 20
                        : variant === 'inEntity' || variant === 'inKnowledge'
                          ? 30
                          : 0,
                    left: 0,
                  }}
                >
                  <Pie
                    data={data}
                    dataKey="value"
                    nameKey="label"
                    cx="50%"
                    cy="50%"
                    fill="#82ca9d"
                    innerRadius="63%"
                    outerRadius="80%"
                    label={
                      variant === 'inEntity' || variant === 'inKnowledge'
                        ? this.renderLabel
                        : this.renderSimpleLabel
                    }
                    labelLine={true}
                    paddingAngle={5}
                  >
                    {data.map((entry, index) => (
                      <Cell
                        key={index}
                        fill={itemColor(entry.label)}
                        stroke="#28353a"
                      />
                    ))}
                  </Pie>
                  {variant === 'inLine' && <Legend margin={{ bottom: 20 }} />}
                </PieChart>
              </ResponsiveContainer>
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
                  {t('No entities of this type has been found.')}
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
    const {
      t, classes, title, variant, height,
    } = this.props;
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
          <Paper classes={{ root: classes.paper }} elevation={2}>
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
  t: PropTypes.func,
  fld: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(EntityStixSightingRelationshipsDonut);
