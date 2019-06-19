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
import { QueryRenderer } from '../../../relay/environment';
import inject18n from '../../../components/i18n';
import { itemColor } from '../../../utils/Colors';
import ExploreUpdateWidget from '../explore/ExploreUpdateWidget';

const styles = () => ({
  paper: {
    minHeight: 300,
    height: '100%',
    margin: '10px 0 0 0',
    borderRadius: 6,
  },
});

const entityStixRelationsDonutStixRelationDistributionQuery = graphql`
  query EntityStixRelationsDonutStixRelationDistributionQuery(
    $fromId: String
    $toTypes: [String]
    $relationType: String
    $inferred: Boolean
    $resolveInferences: Boolean
    $resolveRelationType: String
    $resolveRelationRole: String
    $resolveRelationToTypes: [String]
    $resolveViaTypes: [EntityRelation]
    $field: String!
    $operation: StatsOperation!
  ) {
    stixRelationsDistribution(
      fromId: $fromId
      toTypes: $toTypes
      relationType: $relationType
      inferred: $inferred
      resolveInferences: $resolveInferences
      resolveRelationType: $resolveRelationType
      resolveRelationRole: $resolveRelationRole
      resolveRelationToTypes: $resolveRelationToTypes
      resolveViaTypes: $resolveViaTypes
      field: $field
      operation: $operation
    ) {
      label
      value
    }
  }
`;

class EntityStixRelationsDonut extends Component {
  constructor(props) {
    super(props);
    this.renderLabel = this.renderLabel.bind(this);
  }

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

  render() {
    const {
      t,
      classes,
      variant,
      title,
      entityId,
      entityType,
      relationType,
      field,
      inferred,
      resolveInferences,
      resolveRelationType,
      resolveRelationRole,
      resolveRelationToTypes,
      resolveViaTypes,
      configuration,
      onUpdate,
      onDelete,
    } = this.props;
    const stixRelationsDistributionVariables = {
      inferred,
      resolveInferences,
      resolveRelationType,
      resolveRelationRole,
      resolveRelationToTypes,
      resolveViaTypes,
      fromId: entityId,
      toTypes: entityType ? [entityType] : null,
      relationType,
      field,
      operation: 'count',
    };
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
          {title || `${t('Distribution:')} ${t(`entity_${entityType}`)}`}
        </Typography>
        {variant === 'explore' ? (
          <ExploreUpdateWidget
            configuration={configuration}
            onUpdate={onUpdate.bind(this)}
            onDelete={onDelete.bind(this)}
          />
        ) : (
          ''
        )}
        <div className='clearfix'/>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <QueryRenderer
            query={entityStixRelationsDonutStixRelationDistributionQuery}
            variables={stixRelationsDistributionVariables}
            render={({ props }) => {
              if (
                props
                && props.stixRelationsDistribution
                && props.stixRelationsDistribution.length > 0
              ) {
                return (
                  <ResponsiveContainer height={300} width="100%">
                    <PieChart
                      margin={{
                        top: 50,
                        right: 12,
                        bottom: 25,
                        left: 0,
                      }}
                    >
                      <Pie
                        data={props.stixRelationsDistribution}
                        dataKey="value"
                        nameKey="label"
                        cx="50%"
                        cy="50%"
                        innerRadius={60}
                        outerRadius={80}
                        fill="#82ca9d"
                        label={this.renderLabel}
                        labelLine={true}
                      >
                        {props.stixRelationsDistribution.map((entry, index) => (
                          <Cell key={index} fill={itemColor(entry.label)} />
                        ))}
                      </Pie>
                    </PieChart>
                  </ResponsiveContainer>
                );
              }
              if (props) {
                return (
                  <div
                    style={{ display: 'table', height: '100%', width: '100%' }}
                  >
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
                <div
                  style={{ display: 'table', height: '100%', width: '100%' }}
                >
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
        </Paper>
      </div>
    );
  }
}

EntityStixRelationsDonut.propTypes = {
  variant: PropTypes.string,
  title: PropTypes.string,
  entityId: PropTypes.string,
  relationType: PropTypes.string,
  entityType: PropTypes.string,
  inferred: PropTypes.bool,
  resolveInferences: PropTypes.bool,
  resolveRelationType: PropTypes.string,
  resolveRelationRole: PropTypes.string,
  resolveRelationToTypes: PropTypes.array,
  resolveViaTypes: PropTypes.array,
  field: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
  onUpdate: PropTypes.func,
  onDelete: PropTypes.func,
  configuration: PropTypes.object,
};

export default compose(
  inject18n,
  withStyles(styles),
)(EntityStixRelationsDonut);
