import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import {
  BarChart,
  ResponsiveContainer,
  CartesianGrid,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
} from 'recharts';
import { withTheme, withStyles } from '@material-ui/core/styles';
import CircularProgress from '@material-ui/core/CircularProgress';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import { QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import { monthsAgo, now, numberOfDays } from '../../../../utils/Time';

const styles = () => ({
  paper: {
    minHeight: 280,
    height: '100%',
    margin: '4px 0 0 0',
    padding: '0 0 10px 0',
    borderRadius: 6,
  },
  chip: {
    fontSize: 10,
    height: 20,
    marginLeft: 10,
  },
});

const stixCoreObjectReporstVerticalBarsTimeSeriesQuery = graphql`
  query StixCoreObjectSoftwareVerticalBarsTimeSeriesQuery(
    $objectId: String
    $field: String!
    $operation: StatsOperation!
    $startDate: DateTime!
    $endDate: DateTime!
    $interval: String!
  ) {
    campaignsTimeSeries(
      objectId: $objectId
      field: $field
      operation: $operation
      startDate: $startDate
      endDate: $endDate
      interval: $interval
    ) {
      date
      value
    }
  }
`;

class SoftwareVerticalBars extends Component {
  renderContent() {
    const {
      t,
      md,
      nsd,
      softwareType,
      startDate,
      endDate,
      stixCoreObjectId,
      theme,
    } = this.props;
    const interval = 'day';
    const finalStartDate = startDate || monthsAgo(12);
    const finalEndDate = endDate || now();
    const days = numberOfDays(finalStartDate, finalEndDate);
    let tickFormatter = md;
    if (days <= 30) {
      tickFormatter = nsd;
    }
    const softwareTimeSeriesVariables = {
      authorId: null,
      objectId: stixCoreObjectId,
      softwareType: softwareType || null,
      field: 'created_at',
      operation: 'count',
      startDate: finalStartDate,
      endDate: finalEndDate,
      interval,
    };
    return (
      <QueryRenderer
        query={stixCoreObjectReporstVerticalBarsTimeSeriesQuery}
        variables={softwareTimeSeriesVariables}
        render={({ props }) => {
          if (props && props.campaignsTimeSeries) {
            return (
              <ResponsiveContainer height="100%" width="100%">
                <BarChart
                  data={props.campaignsTimeSeries}
                  margin={{
                    top: 20,
                    right: 50,
                    bottom: 20,
                    left: -10,
                  }}
                >
                  <CartesianGrid
                    strokeDasharray="2 2"
                    stroke={theme.palette.action.grid}
                  />
                  <XAxis
                    dataKey="date"
                    stroke={theme.palette.text.primary}
                    interval={interval}
                    angle={-45}
                    textAnchor="end"
                    tickFormatter={tickFormatter}
                  />
                  <YAxis stroke={theme.palette.text.primary} />
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
                    labelFormatter={tickFormatter}
                  />
                  <Bar
                    fill={theme.palette.primary.main}
                    dataKey="value"
                    barSize={5}
                  />
                </BarChart>
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
        <Typography variant="h4" gutterBottom={true}>
          {title || t('Software history')}
        </Typography>
        {variant !== 'inLine' ? (
          <Paper classes={{ root: classes.paper }} elevation={2}>
            {this.renderContent()}
          </Paper>
        ) : (
          this.renderContent()
        )}
      </div>
    );
  }
}

SoftwareVerticalBars.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  stixCoreObjectId: PropTypes.string,
  t: PropTypes.func,
  md: PropTypes.func,
};

export default compose(
  inject18n,
  withTheme,
  withStyles(styles),
)(SoftwareVerticalBars);
