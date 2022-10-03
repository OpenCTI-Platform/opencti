import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import {
  ResponsiveContainer,
  CartesianGrid,
  AreaChart,
  XAxis,
  YAxis,
  Area,
  Tooltip,
  Legend,
} from 'recharts';
import { withStyles, withTheme } from '@material-ui/core/styles';
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

// const cyioCoreObjectVulnerabilitiesAreaChartQuery = graphql`
//   query CyioCoreObjectVulnerabilitiesAreaChartQuery(
//     $objectId: String
//     $authorId: String
//     $reportClass: String
//     $field: String!
//     $operation: StatsOperation!
//     $startDate: DateTime!
//     $endDate: DateTime!
//     $interval: String!
//   ) {
//     reportsTimeSeries(
//       objectId: $objectId
//       authorId: $authorId
//       reportType: $reportClass
//       field: $field
//       operation: $operation
//       startDate: $startDate
//       endDate: $endDate
//       interval: $interval
//     ) {
//       date
//       value
//     }
//   }
// `;

const data = [
  {
    name: 'Jan A',
    accepted: 4000,
    pv: 2400,
    amt: 2400,
  },
  {
    name: 'Jan B',
    accepted: 3000,
    pv: 1398,
    amt: 2210,
  },
  {
    name: 'Jan C',
    accepted: 2000,
    pv: 3800,
    amt: 2290,
  },
  {
    name: 'Jan D',
    accepted: 2780,
    pv: 3908,
    amt: 2000,
  },
  {
    name: 'Jan E',
    accepted: 1890,
    pv: 4800,
    amt: 2181,
  },
  {
    name: 'Jan F',
    accepted: 2390,
    pv: 3800,
    amt: 2500,
  },
  {
    name: 'Jan G',
    accepted: 3770,
    pv: 4300,
    amt: 2100,
  },
  {
    name: 'Jan H',
    accepted: 3490,
    pv: 3300,
    amt: 2200,
  },
  {
    name: 'Jan I',
    accepted: 3490,
    pv: 3500,
    amt: 2150,
  },
  {
    name: 'Jan J',
    accepted: 4790,
    pv: 5300,
    amt: 2850,
  },
  {
    name: 'Jan K',
    accepted: 3790,
    pv: 4600,
    amt: 2960,
  },
  {
    name: 'Jan L',
    accepted: 3490,
    pv: 4700,
    amt: 2770,
  },
];

class CyioCoreObjectTotalActiveRiskAreaChart extends Component {
  renderContent() {
    const {
      t,
      md,
      nsd,
      reportType,
      startDate,
      endDate,
      stixCoreObjectId,
      authorId,
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
    let reportsTimeSeriesVariables;
    if (authorId) {
      reportsTimeSeriesVariables = {
        authorId,
        objectId: null,
        reportType: reportType || null,
        field: 'created_at',
        operation: 'count',
        startDate: finalStartDate,
        endDate: finalEndDate,
        interval,
      };
    } else {
      reportsTimeSeriesVariables = {
        authorId: null,
        objectId: stixCoreObjectId,
        reportType: reportType || null,
        field: 'created_at',
        operation: 'count',
        startDate: finalStartDate,
        endDate: finalEndDate,
        interval,
      };
    }
    return (
      // <QueryRenderer
      //   query={cyioCoreObjectVulnerabilitiesAreaChartQuery}
      //   variables={reportsTimeSeriesVariables}
      //   render={({ props }) => {
      //     if (props && props.reportsTimeSeries) {
      //       return (
      <ResponsiveContainer height="100%" width="100%">
        <AreaChart
          // data={props.reportsTimeSeries}
          data={data}
          margin={{
            top: 20,
            right: 0,
            bottom: 20,
            left: -10,
          }}
        >
          <CartesianGrid
            strokeDasharray="2 2"
            // stroke={theme.palette.primary.main}
            stroke='rgba(241, 241, 242, 0.35)'
            vertical={false}
          />
          <XAxis
            dataKey="name"
            stroke={theme.palette.text.primary}
            // interval={interval}
            textAnchor="end"
          // angle={-30}
          // tickFormatter={tickFormatter}
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
          // labelFormatter={tickFormatter}
          />
          <Legend />
          <Area
            dataKey="accepted"
            stroke={theme.palette.primary.main}
            strokeWidth={2}
            // fill={theme.palette.primary.main}
            fill='#49B8FC'
            fillOpacity={0.3}
          />
        </AreaChart>
      </ResponsiveContainer>
      //       );
      //     }
      //     if (props) {
      //       return (
      //         <div style={{ display: 'table', height: '100%', width: '100%' }}>
      //           <span
      //             style={{
      //               display: 'table-cell',
      //               verticalAlign: 'middle',
      //               textAlign: 'center',
      //             }}
      //           >
      //             {t('No entities of this type has been found.')}
      //           </span>
      //         </div>
      //       );
      //     }
      //     return (
      //       <div style={{ display: 'table', height: '100%', width: '100%' }}>
      //         <span
      //           style={{
      //             display: 'table-cell',
      //             verticalAlign: 'middle',
      //             textAlign: 'center',
      //           }}
      //         >
      //           <CircularProgress size={40} thickness={2} />
      //         </span>
      //       </div>
      //     );
      //   }}
      // />
    );
  }

  render() {
    const {
      t, classes, title, variant, height,
    } = this.props;
    return (
      <div style={{ height: height || '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {title || t('Total Active Risks')}
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

CyioCoreObjectTotalActiveRiskAreaChart.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  stixCoreObjectId: PropTypes.string,
  authorId: PropTypes.string,
  t: PropTypes.func,
  md: PropTypes.func,
  nsd: PropTypes.func,
};

export default compose(
  inject18n,
  withTheme,
  withStyles(styles),
)(CyioCoreObjectTotalActiveRiskAreaChart);
