import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import ResponsiveContainer from 'recharts/lib/component/ResponsiveContainer';
import PieChart from 'recharts/lib/chart/PieChart';
import Pie from 'recharts/lib/polar/Pie';
import Cell from 'recharts/lib/component/Cell';
import { withStyles } from '@material-ui/core/styles';
import CircularProgress from '@material-ui/core/CircularProgress';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import { QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import { itemColor } from '../../../../utils/Colors';

const styles = () => ({
  paper: {
    minHeight: 280,
    height: '100%',
    margin: '10px 0 0 0',
    borderRadius: 6,
  },
  paperExplore: {
    height: '100%',
    margin: 0,
    padding: 0,
    borderRadius: 6,
  },
  updateButton: {
    float: 'right',
    margin: '7px 10px 0 0',
  },
});

const entityStixCoreRelationshipsDonutStixCoreRelationshipDistributionQuery = graphql`
  query EntityStixCoreRelationshipsDonutStixCoreRelationshipDistributionQuery(
    $fromId: String!
    $toTypes: [String]
    $relationship_type: String
    $startDate: DateTime
    $endDate: DateTime
    $field: String!
    $operation: StatsOperation!
    $isTo: Boolean
  ) {
    stixCoreRelationshipsDistribution(
      fromId: $fromId
      toTypes: $toTypes
      relationship_type: $relationship_type
      startDate: $startDate
      endDate: $endDate
      field: $field
      operation: $operation
      isTo: $isTo
    ) {
      label
      value
    }
  }
`;

class EntityStixCoreRelationshipsDonut extends Component {
  constructor(props) {
    super(props);
    this.renderLabel = this.renderLabel.bind(this);
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
      t,
      entityId,
      entityType,
      variant,
      relationshipType,
      field,
      height,
      startDate,
      endDate,
      isTo,
    } = this.props;
    const stixCoreRelationshipsDistributionVariables = {
      fromId: entityId,
      toTypes: entityType ? [entityType] : null,
      startDate: startDate || null,
      endDate: endDate || null,
      relationship_type: relationshipType,
      field,
      operation: 'count',
      isTo: isTo || false,
    };
    return (
      <QueryRenderer
        query={
          entityStixCoreRelationshipsDonutStixCoreRelationshipDistributionQuery
        }
        variables={stixCoreRelationshipsDistributionVariables}
        render={({ props }) => {
          if (
            props
            && props.stixCoreRelationshipsDistribution
            && props.stixCoreRelationshipsDistribution.length > 0
          ) {
            return (
              <ResponsiveContainer height={height} width="100%">
                <PieChart
                  margin={{
                    top: variant === 'inLine' ? 40 : 0,
                    right: 0,
                    bottom: 0,
                    left: 0,
                  }}
                >
                  <Pie
                    data={props.stixCoreRelationshipsDistribution}
                    dataKey="value"
                    nameKey="label"
                    cx="50%"
                    cy="50%"
                    innerRadius={70}
                    outerRadius={100}
                    fill="#82ca9d"
                    label={this.renderLabel}
                    labelLine={true}
                    paddingAngle={5}
                  >
                    {props.stixCoreRelationshipsDistribution.map(
                      (entry, index) => (
                        <Cell
                          key={index}
                          fill={itemColor(entry.label)}
                          stroke="#28353a"
                        />
                      ),
                    )}
                  </Pie>
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
      t, classes, title, entityType, variant, height,
    } = this.props;
    return (
      <div style={{ height: height || '100%' }}>
        <Typography
          variant={variant === 'inLine' ? 'h3' : 'h4'}
          gutterBottom={true}
        >
          {title || `${t('Distribution:')} ${t(`entity_${entityType}s`)}`}
        </Typography>
        {variant === 'inLine' ? (
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

EntityStixCoreRelationshipsDonut.propTypes = {
  title: PropTypes.string,
  variant: PropTypes.string,
  entityId: PropTypes.string,
  relationshipType: PropTypes.string,
  entityType: PropTypes.string,
  startDate: PropTypes.string,
  endDate: PropTypes.string,
  field: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
  configuration: PropTypes.object,
  handleOpenConfig: PropTypes.func,
  isTo: PropTypes.bool,
};

export default compose(
  inject18n,
  withStyles(styles),
)(EntityStixCoreRelationshipsDonut);
