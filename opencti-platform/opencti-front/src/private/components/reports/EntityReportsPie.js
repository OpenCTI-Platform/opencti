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

const styles = () => ({
  paper: {
    minHeight: 280,
    height: '100%',
    margin: '10px 0 0 0',
    padding: 0,
    borderRadius: 6,
  },
});
const RADIAN = Math.PI / 180;
const renderCustomizedLabel = ({
  cx,
  cy,
  midAngle,
  innerRadius,
  outerRadius,
  percent,
}) => {
  const radius = innerRadius + (outerRadius - innerRadius) * 0.5;
  const x = cx + radius * Math.cos(-midAngle * RADIAN);
  const y = cy + radius * Math.sin(-midAngle * RADIAN);

  return (
    <text
      x={x}
      y={y}
      fill="white"
      textAnchor={x > cx ? 'start' : 'end'}
      dominantBaseline="central"
    >
      {`${(percent * 100).toFixed(0)}%`}
    </text>
  );
};

const entityReportsPieReportsDistributionQuery = graphql`
  query EntityReportsPieReportsDistributionQuery(
    $objectId: String
    $field: String!
    $operation: StatsOperation!
  ) {
    reportsDistribution(
      objectId: $objectId
      field: $field
      operation: $operation
    ) {
      label
      value
    }
  }
`;

class EntityReportsPie extends Component {
  render() {
    const {
      t, classes, entityId, field,
    } = this.props;
    const reportsDistributionVariables = {
      objectId: entityId,
      field: field || 'report_class',
      operation: 'count',
    };
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Reports distribution')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <QueryRenderer
            query={entityReportsPieReportsDistributionQuery}
            variables={reportsDistributionVariables}
            render={({ props }) => {
              if (
                props
                && props.reportsDistribution
                && props.reportsDistribution.length > 0
              ) {
                return (
                  <ResponsiveContainer height={280} width="100%">
                    <PieChart
                      margin={{
                        top: 50,
                        right: 12,
                        bottom: 25,
                        left: 0,
                      }}
                    >
                      <Pie
                        data={props.reportsDistribution}
                        dataKey="value"
                        nameKey="label"
                        cx="50%"
                        cy="50%"
                        outerRadius={100}
                        fill="#82ca9d"
                        label={renderCustomizedLabel}
                        labelLine={false}
                      >
                        {props.reportsDistribution.map((entry, index) => (
                          <Cell key={index} fill={itemColor(entry.label)} />
                        ))}
                      </Pie>
                      <Legend
                        verticalAlign="bottom"
                        wrapperStyle={{ paddingTop: 20 }}
                      />
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

EntityReportsPie.propTypes = {
  entityId: PropTypes.string,
  field: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(inject18n, withStyles(styles))(EntityReportsPie);
