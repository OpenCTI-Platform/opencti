import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql } from 'react-relay';
import withTheme from '@mui/styles/withTheme';
import withStyles from '@mui/styles/withStyles';
import CircularProgress from '@mui/material/CircularProgress';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Chart from 'react-apexcharts';
import { QueryRenderer } from '../../../../relay/environment';
import { monthsAgo, now } from '../../../../utils/Time';
import inject18n from '../../../../components/i18n';
import { areaChartOptions } from '../../../../utils/Charts';
import { simpleNumberFormat } from '../../../../utils/Number';

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
    $fromId: StixRef
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
      fsd,
      field,
      startDate,
      endDate,
      theme,
    } = this.props;
    const interval = 'day';
    const finalStartDate = startDate || monthsAgo(12);
    const finalEndDate = endDate || now();
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
            const chartData = props.stixCoreRelationshipsTimeSeries.map(
              (entry) => ({
                x: new Date(entry.date),
                y: entry.value,
              }),
            );
            return (
              <Chart
                options={areaChartOptions(
                  theme,
                  true,
                  fsd,
                  simpleNumberFormat,
                  undefined,
                )}
                series={[
                  {
                    name: t('Number of relationships'),
                    data: chartData,
                  },
                ]}
                type="area"
                width="100%"
                height="100%"
              />
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
