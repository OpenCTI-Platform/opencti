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
import { withStyles, withTheme } from '@material-ui/core/styles';
import CircularProgress from '@material-ui/core/CircularProgress';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import { QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import { monthsAgo, now } from '../../../../utils/Time';

const styles = () => ({
  paper: {
    minHeight: 280,
    height: '100%',
    margin: '4px 0 0 0',
    padding: '1rem',
    borderRadius: 6,
  },
  chip: {
    fontSize: 10,
    height: 20,
    marginLeft: 10,
  },
});

// const stixCoreObjectReporstVerticalBarsTimeSeriesQuery = graphql`
//   query StixCoreObjectReportsVerticalBarsTimeSeriesQuery(
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
    uv: 4000,
    pv: 2400,
    amt: 2400,
  },
  {
    name: 'Jan B',
    uv: 3000,
    pv: 1398,
    amt: 2210,
  },
  {
    name: 'Jan C',
    uv: 2000,
    pv: 3800,
    amt: 2290,
  },
  {
    name: 'Jan D',
    uv: 2780,
    pv: 3908,
    amt: 2000,
  },
  {
    name: 'Jan E',
    uv: 1890,
    pv: 4800,
    amt: 2181,
  },
  {
    name: 'Jan F',
    uv: 2390,
    pv: 3800,
    amt: 2500,
  },
  {
    name: 'Jan G',
    uv: 3770,
    pv: 4300,
    amt: 2100,
  },
  {
    name: 'Jan H',
    uv: 3490,
    pv: 3300,
    amt: 2200,
  },
  {
    name: 'Jan I',
    uv: 3490,
    pv: 3500,
    amt: 2150,
  },
  {
    name: 'Jan J',
    uv: 4790,
    pv: 5300,
    amt: 2850,
  },
  {
    name: 'Jan K',
    uv: 3790,
    pv: 4600,
    amt: 2960,
  },
  {
    name: 'Jan L',
    uv: 3490,
    pv: 4700,
    amt: 2770,
  },
];

class CyioCoreObjectRiskSeverityVerticalBars extends Component {
  renderContent() {
    const {
      t,
      md,
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
      //   query={stixCoreObjectReporstVerticalBarsTimeSeriesQuery}
      //   variables={reportsTimeSeriesVariables}
      //   render={({ props }) => {
      //     if (props && props.reportsTimeSeries) {
      //       return (
      <ResponsiveContainer height="100%" width="100%">
        <BarChart
          layout='vertical'
          // data={props.reportsTimeSeries}
          data={data}
          margin={{
            top: 20,
            right: 20,
            bottom: 0,
            left: 0,
          }}
          barGap={0}
        >
          <CartesianGrid
            strokeDasharray="2 2"
            stroke='rgba(241, 241, 242, 0.35)'
            // stroke={theme.palette.action.grid}
            vertical={false}
          />
          <XAxis
            // dataKey="name"
            type='number'
            stroke={theme.palette.text.primary}
          // interval={interval}
          // angle={-45}
          // textAnchor="end"
          // tickFormatter={md}
          />
          <YAxis type='category' dataKey='name' stroke={theme.palette.text.primary} />
          <Tooltip
            cursor={{
              fill: 'rgba(0, 0, 0, 0.2)',
              stroke: 'rgba(0, 0, 0, 0.2)',
              strokeWidth: 2,
            }}
            contentStyle={{
              backgroundColor: '#1F2842',
              fontSize: 12,
              border: '1px solid #06102D',
              borderRadius: 10,
            }}
            labelFormatter={md}
          />
          <Bar
            // fill={theme.palette.primary.main}
            fill="#075AD3"
            dataKey="amt"
            barSize={20}
          />
        </BarChart>
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
          {title || t('Top N Risks by Severity')}
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

CyioCoreObjectRiskSeverityVerticalBars.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  stixCoreObjectId: PropTypes.string,
  authorId: PropTypes.string,
  t: PropTypes.func,
  md: PropTypes.func,
};

export default compose(
  inject18n,
  withTheme,
  withStyles(styles),
)(CyioCoreObjectRiskSeverityVerticalBars);
