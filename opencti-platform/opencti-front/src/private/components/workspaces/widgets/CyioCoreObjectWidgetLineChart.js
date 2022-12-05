import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import {
  ResponsiveContainer,
  CartesianGrid,
  AreaChart,
  XAxis,
  YAxis,
  Area,
  Tooltip,
} from 'recharts';
import { withStyles, withTheme } from '@material-ui/core/styles';
import CircularProgress from '@material-ui/core/CircularProgress';
import Typography from '@material-ui/core/Typography';
import { QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import { monthsAgo, now, numberOfDays } from '../../../../utils/Time';
import {
  dashboardQueryRiskTimeSeries,
  dashboardQueryAssetsTimeSeries,
} from '../../settings/DashboardQuery';

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

class CyioCoreObjectWidgetLineChart extends Component {
  renderLineChartQuery() {
    const { widget, t } = this.props;
    switch (widget.config && widget.config.queryType) {
      case 'assetsTimeSeries':
        return this.renderAssetChart();
      case 'risksTimSeries':
      case 'risksTimeSeries':
        return this.renderRiskChart();
      default:
        return (
          <div style={{ display: 'table', height: '100%', width: '100%' }}>
            <span
              style={{
                display: 'table-cell',
                verticalAlign: 'middle',
                textAlign: 'center',
              }}
            >
              {t('Not implemented yet.')}
            </span>
          </div>
        );
    }
  }

  renderAssetChart() {
    const {
      t,
      md,
      nsd,
      widget,
      startDate,
      endDate,
      theme,
    } = this.props;
    const interval = 'month';
    const finalStartDate = startDate || '1970-01-01T00:00:00Z';
    const finalEndDate = endDate || now();
    const days = numberOfDays(finalStartDate, finalEndDate);
    let tickFormatter = md;
    if (days <= 30) {
      tickFormatter = nsd;
    }
    const areaChartVariables = {
      ...widget.config.variables,
      startDate: finalStartDate,
      endDate: finalEndDate,
      interval,
    };
    return (
      <>
        <Typography variant="h4" gutterBottom={true}>
          {widget.config.name || t('Component')}
        </Typography>
        <QueryRenderer
          query={dashboardQueryAssetsTimeSeries}
          variables={areaChartVariables}
          render={({ props }) => {
            if (props && props[widget.config.queryType]) {
              return (
                <ResponsiveContainer height="100%" width="100%">
                  <AreaChart
                    data={props[widget.config.queryType]}
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
                      dataKey="label"
                      stroke={theme.palette.text.primary}
                      interval={interval}
                      textAnchor="end"
                      // angle={-30}
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
                        backgroundColor: '#1F2842',
                        fontSize: 12,
                        border: '1px solid #06102D',
                        borderRadius: 10,
                      }}
                      labelFormatter={tickFormatter}
                    />
                    <Area
                      dataKey='value'
                      stroke={theme.palette.primary.main}
                      strokeWidth={2}
                    // fill={theme.palette.primary.main}
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
      </>
    );
  }

  renderRiskChart() {
    const {
      t,
      md,
      nsd,
      widget,
      startDate,
      endDate,
      theme,
    } = this.props;
    const interval = 'month';
    const finalStartDate = startDate || '1970-01-01T00:00:00Z';
    const finalEndDate = endDate || now();
    const days = numberOfDays(finalStartDate, finalEndDate);
    let tickFormatter = md;
    if (days <= 30) {
      tickFormatter = nsd;
    }
    const areaChartVariables = {
      ...widget.config.variables,
      startDate: finalStartDate,
      endDate: finalEndDate,
      interval,
    };
    return (
      <>
        <Typography variant="h4" gutterBottom={true}>
          {widget.config.name || t('Component')}
        </Typography>
        <QueryRenderer
          query={dashboardQueryRiskTimeSeries}
          variables={areaChartVariables}
          render={({ props }) => {
            if (props && props[widget.config.queryType]) {
              return (
                <ResponsiveContainer height="100%" width="100%">
                  <AreaChart
                    data={props[widget.config.queryType]}
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
                      dataKey="label"
                      stroke={theme.palette.text.primary}
                      interval={interval}
                      textAnchor="end"
                      // angle={-30}
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
                        backgroundColor: '#1F2842',
                        fontSize: 12,
                        border: '1px solid #06102D',
                        borderRadius: 10,
                      }}
                      labelFormatter={tickFormatter}
                    />
                    <Area
                      dataKey='value'
                      stroke={theme.palette.primary.main}
                      strokeWidth={2}
                    // fill={theme.palette.primary.main}
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
      </>
    );
  }

  render() {
    const {
      height,
    } = this.props;
    return (
      <div style={{ height: height || '100%' }}>
        {this.renderLineChartQuery()}
      </div>
    );
  }
}

CyioCoreObjectWidgetLineChart.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  md: PropTypes.func,
  nsd: PropTypes.func,
  widget: PropTypes.object,
};

export default compose(
  inject18n,
  withTheme,
  withStyles(styles),
)(CyioCoreObjectWidgetLineChart);
