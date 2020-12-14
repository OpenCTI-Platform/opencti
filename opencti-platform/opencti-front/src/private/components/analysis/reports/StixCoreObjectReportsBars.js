import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import BarChart from 'recharts/lib/chart/BarChart';
import XAxis from 'recharts/lib/cartesian/XAxis';
import YAxis from 'recharts/lib/cartesian/YAxis';
import Cell from 'recharts/lib/component/Cell';
import CartesianGrid from 'recharts/lib/cartesian/CartesianGrid';
import Bar from 'recharts/lib/cartesian/Bar';
import ResponsiveContainer from 'recharts/lib/component/ResponsiveContainer';
import Tooltip from 'recharts/lib/component/Tooltip';
import { withStyles } from '@material-ui/core/styles';
import CircularProgress from '@material-ui/core/CircularProgress';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import { QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import { itemColor } from '../../../../utils/Colors';
import Theme from '../../../../components/ThemeDark';
import { truncate } from '../../../../utils/String';

const styles = () => ({
  paper: {
    height: 300,
    minHeight: 300,
    maxHeight: 300,
    margin: '10px 0 0 0',
    padding: 0,
    borderRadius: 6,
  },
});

const stixCoreObjectReportsBarsDistributionQuery = graphql`
  query StixCoreObjectReportsBarsDistributionQuery(
    $objectId: String
    $field: String!
    $operation: StatsOperation!
    $limit: Int
  ) {
    reportsDistribution(
      objectId: $objectId
      field: $field
      operation: $operation
      limit: $limit
    ) {
      label
      value
      entity {
        ... on Identity {
          name
        }
      }
    }
  }
`;

const tickFormatter = (title) => truncate(title, 10);

class StixCoreObjectReportsBars extends Component {
  render() {
    const {
      t, classes, stixCoreObjectId, field, title,
    } = this.props;
    const reportsDistributionVariables = {
      objectId: stixCoreObjectId,
      field: field || 'report_types',
      operation: 'count',
      limit: 8,
    };
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {title || t('Reports distribution')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <QueryRenderer
            query={stixCoreObjectReportsBarsDistributionQuery}
            variables={reportsDistributionVariables}
            render={({ props }) => {
              if (
                props
                && props.reportsDistribution
                && props.reportsDistribution.length > 0
              ) {
                return (
                  <ResponsiveContainer height={280} width="100%">
                    <BarChart
                      layout="vertical"
                      data={props.reportsDistribution}
                      margin={{
                        top: 20,
                        right: 20,
                        bottom: 0,
                        left: 20,
                      }}
                    >
                      <XAxis
                        type="number"
                        dataKey="value"
                        stroke="#ffffff"
                        allowDecimals={false}
                      />
                      <YAxis
                        stroke="#ffffff"
                        dataKey={field.includes('.') ? 'entity.name' : 'label'}
                        type="category"
                        angle={-30}
                        textAnchor="end"
                        tickFormatter={tickFormatter}
                      />
                      <CartesianGrid strokeDasharray="2 2" stroke="#0f181f" />
                      <Tooltip
                        cursor={{
                          fill: 'rgba(0, 0, 0, 0.2)',
                          stroke: 'rgba(0, 0, 0, 0.2)',
                          strokeWidth: 2,
                        }}
                        contentStyle={{
                          backgroundColor: 'rgba(255, 255, 255, 0.1)',
                          fontSize: 12,
                          borderRadius: 10,
                        }}
                      />
                      <Bar
                        fill={Theme.palette.primary.main}
                        dataKey="value"
                        barSize={15}
                      >
                        {props.reportsDistribution.map((entry, index) => (
                          <Cell
                            key={`cell-${index}`}
                            fill={itemColor(entry.entity.name)}
                          />
                        ))}
                      </Bar>
                    </BarChart>
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

StixCoreObjectReportsBars.propTypes = {
  stixCoreObjectId: PropTypes.string,
  title: PropTypes.string,
  field: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixCoreObjectReportsBars);
