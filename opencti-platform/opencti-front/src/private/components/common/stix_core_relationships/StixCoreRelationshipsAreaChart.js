import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql } from 'react-relay';
import {
  AreaChart,
  ResponsiveContainer,
  CartesianGrid,
  Area,
  XAxis,
  YAxis,
  Tooltip,
} from 'recharts';
import withTheme from '@mui/styles/withTheme';
import withStyles from '@mui/styles/withStyles';
import CircularProgress from '@mui/material/CircularProgress';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import { QueryRenderer } from '../../../../relay/environment';
import { monthsAgo, now, numberOfDays } from '../../../../utils/Time';
import inject18n from '../../../../components/i18n';

const styles = () => ({
  paper: {
    height: '100%',
    margin: '4px 0 0 0',
    borderRadius: 6,
  },
  paperExplore: {
    height: '100%',
    margin: 0,
    padding: '0 0 10px 0',
    borderRadius: 6,
  },
  chip: {
    fontSize: 10,
    height: 20,
    marginLeft: 10,
  },
  updateButton: {
    float: 'right',
    margin: '7px 10px 0 0',
  },
});

const stixCoreRelationshipsAreaChartStixCoreRelationshipTimeSeriesQuery = graphql`
  query StixCoreRelationshipsAreaChartStixCoreRelationshipTimeSeriesQuery(
    $fromId: String
    $toTypes: [String]
    $relationship_type: String
    $field: String!
    $operation: StatsOperation!
    $startDate: DateTime!
    $endDate: DateTime!
    $interval: String!
  ) {
    stixCoreRelationshipsTimeSeries(
      fromId: $fromId
      toTypes: $toTypes
      relationship_type: $relationship_type
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

class StixCoreRelationshipsAreaChart extends Component {
  constructor(props) {
    super(props);
    this.state = { period: 36, interval: 2 };
  }

  renderContent() {
    const {
      t,
      toTypes,
      relationshipType,
      md,
      nsd,
      field,
      startDate,
      endDate,
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
    const stixCoreRelationshipsTimeSeriesVariables = {
      toTypes,
      relationship_type: relationshipType,
      field: field || 'created_at',
      operation: 'count',
      startDate: finalStartDate,
      endDate: finalEndDate,
      interval,
    };
    return (
      <QueryRenderer
        query={
          stixCoreRelationshipsAreaChartStixCoreRelationshipTimeSeriesQuery
        }
        variables={stixCoreRelationshipsTimeSeriesVariables}
        render={({ props }) => {
          if (props && props.stixCoreRelationshipsTimeSeries) {
            return (
              <ResponsiveContainer height="100%" width="100%">
                <AreaChart
                  data={props.stixCoreRelationshipsTimeSeries}
                  margin={{
                    top: 20,
                    right: 50,
                    bottom: 35,
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
                  <YAxis stroke={theme.palette.text.primary} />
                  <Area
                    type="monotone"
                    stroke={theme.palette.primary.main}
                    dataKey="value"
                  />
                </AreaChart>
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
    const { t, classes, title, variant, height } = this.props;
    return (
      <div style={{ height: height || '100%' }}>
        <Typography
          variant={variant === 'inEntity' ? 'h3' : 'h4'}
          gutterBottom={true}
        >
          {title || t('History of relationships')}
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

StixCoreRelationshipsAreaChart.propTypes = {
  variant: PropTypes.string,
  title: PropTypes.string,
  relationshipType: PropTypes.string,
  field: PropTypes.string,
  startDate: PropTypes.string,
  endDate: PropTypes.string,
  toTypes: PropTypes.array,
  theme: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  nsd: PropTypes.func,
};

export default compose(
  inject18n,
  withTheme,
  withStyles(styles),
)(StixCoreRelationshipsAreaChart);
