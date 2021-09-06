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
import { monthsAgo, now } from '../../../../utils/Time';
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

const entityStixCoreRelationshipsVerticalBarsStixCoreRelationshipTimeSeriesQuery = graphql`
  query EntityStixCoreRelationshipsVerticalBarsStixCoreRelationshipTimeSeriesQuery(
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

class EntityStixCoreRelationshipsVerticalBars extends Component {
  constructor(props) {
    super(props);
    this.state = { period: 36, interval: 2 };
  }

  renderContent() {
    const {
      t,
      entityId,
      toTypes,
      relationshipType,
      md,
      field,
      startDate,
      endDate,
      theme,
    } = this.props;
    const interval = 'day';
    const finalStartDate = startDate || monthsAgo(12);
    const finalEndDate = endDate || now();
    const stixCoreRelationshipsTimeSeriesVariables = {
      fromId: entityId || null,
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
          entityStixCoreRelationshipsVerticalBarsStixCoreRelationshipTimeSeriesQuery
        }
        variables={stixCoreRelationshipsTimeSeriesVariables}
        render={({ props }) => {
          if (props && props.stixCoreRelationshipsTimeSeries) {
            return (
              <ResponsiveContainer height="100%" width="100%">
                <BarChart
                  data={props.stixCoreRelationshipsTimeSeries}
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
                    tickFormatter={md}
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
                    labelFormatter={md}
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
        <Typography
          variant={variant === 'inEntity' ? 'h3' : 'h4'}
          gutterBottom={true}
        >
          {title || t('History of relationships')}
        </Typography>
        {variant === 'inLine' || variant === 'inEntity' ? (
          this.renderContent()
        ) : (
          <Paper classes={{ root: classes.paper }} elevation={2}>
            {this.renderContent()}
          </Paper>
        )}
      </div>
    );
  }
}

EntityStixCoreRelationshipsVerticalBars.propTypes = {
  variant: PropTypes.string,
  title: PropTypes.string,
  entityId: PropTypes.string,
  relationshipType: PropTypes.string,
  field: PropTypes.string,
  startDate: PropTypes.string,
  endDate: PropTypes.string,
  toTypes: PropTypes.array,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  md: PropTypes.func,
};

export default compose(
  inject18n,
  withTheme,
  withStyles(styles),
)(EntityStixCoreRelationshipsVerticalBars);
