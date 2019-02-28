import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import PieChart from 'recharts/lib/chart/PieChart';
import Pie from 'recharts/lib/polar/Pie';
import Cell from 'recharts/lib/component/Cell';
import Legend from 'recharts/lib/component/Legend';
import ResponsiveContainer from 'recharts/lib/component/ResponsiveContainer';
import { withStyles } from '@material-ui/core/styles';
import CircularProgress from '@material-ui/core/CircularProgress';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import { QueryRenderer } from '../../../relay/environment';
import inject18n from '../../../components/i18n';
import { itemColor } from '../../../utils/Colors';

const styles = theme => ({
  paper: {
    minHeight: 300,
    height: '100%',
    margin: '10px 0 0 0',
    padding: 0,
    backgroundColor: theme.palette.paper.background,
    color: theme.palette.text.main,
    borderRadius: 6,
  },
});
const RADIAN = Math.PI / 180;
const renderCustomizedLabel = ({
  cx, cy, midAngle, innerRadius, outerRadius, percent, index,
}) => {
  const radius = innerRadius + (outerRadius - innerRadius) * 0.5;
  const x = cx + radius * Math.cos(-midAngle * RADIAN);
  const y = cy + radius * Math.sin(-midAngle * RADIAN);

  return (
    <text x={x} y={y} fill="white" textAnchor={x > cx ? 'start' : 'end'} dominantBaseline="central">
      {`${(percent * 100).toFixed(0)}%`}
    </text>
  );
};

const entityStixRelationsPieStixRelationDistributionQuery = graphql`
    query EntityStixRelationsPieStixRelationDistributionQuery($fromId: String, $toTypes: [String], $entityTypes: [String], $relationType: String, $resolveRelationType: String, $resolveInferences: Boolean, $field: String!, $operation: StatsOperation!) {
        stixRelationsDistribution(fromId: $fromId, toTypes: $toTypes, entityTypes: $entityTypes, relationType: $relationType, resolveRelationType: $resolveRelationType, resolveInferences: $resolveInferences, field: $field, operation: $operation) {
            label,
            value
        }
    }
`;

class EntityStixRelationsPie extends Component {
  render() {
    const {
      t,
      classes,
      entityId,
      entityType,
      relationType,
      field,
      entityTypes,
      resolveInferences,
      resolveRelationType,
    } = this.props;
    const stixRelationsDistributionVariables = {
      fromId: entityId,
      toTypes: entityType ? [entityType] : null,
      entityTypes: entityTypes || null,
      resolveInferences,
      resolveRelationType,
      relationType,
      field,
      operation: 'count',
    };
    return (
      <div style={{ height: '100%' }}>
        <Typography variant='h4' gutterBottom={true}>
          {t('Distribution:')} {t(`entity_${entityType}`)}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <QueryRenderer
            query={entityStixRelationsPieStixRelationDistributionQuery}
            variables={stixRelationsDistributionVariables}
            render={({ props }) => {
              if (props && props.stixRelationsDistribution && props.stixRelationsDistribution.length > 0) {
                return (
                  <ResponsiveContainer height={300} width='100%'>
                    <PieChart margin={{
                      top: 50, right: 12, bottom: 25, left: 0,
                    }}>
                      <Pie data={props.stixRelationsDistribution} dataKey='value' nameKey='label' cx='50%' cy='50%' outerRadius={100} fill='#82ca9d' label={renderCustomizedLabel} labelLine={false}>
                        {
                          props.stixRelationsDistribution.map((entry, index) => <Cell key={index} fill={itemColor(entry.label)}/>)
                        }
                      </Pie>
                      <Legend verticalAlign='bottom' wrapperStyle={{ paddingTop: 20 }}/>
                    </PieChart>
                  </ResponsiveContainer>
                );
              }
              if (props) {
                return (
                  <div style={{ textAlign: 'center', paddingTop: 140 }}>{t('No entities of this type has been found.')}</div>
                );
              }
              return (
                <div style={{ textAlign: 'center', paddingTop: 140 }}><CircularProgress size={40} thickness={2}/></div>
              );
            }}
          />
        </Paper>
      </div>
    );
  }
}

EntityStixRelationsPie.propTypes = {
  entityId: PropTypes.string,
  relationType: PropTypes.string,
  entityType: PropTypes.string,
  resolveInferences: PropTypes.bool,
  resolveRelationType: PropTypes.string,
  entityTypes: PropTypes.array,
  field: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(EntityStixRelationsPie);
