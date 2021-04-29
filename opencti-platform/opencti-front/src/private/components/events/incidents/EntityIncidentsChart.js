import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import {
  LineChart,
  ResponsiveContainer,
  CartesianGrid,
  Line,
  XAxis,
  YAxis,
} from 'recharts';
import { withStyles } from '@material-ui/core/styles';
import CircularProgress from '@material-ui/core/CircularProgress';
import Paper from '@material-ui/core/Paper';
import Chip from '@material-ui/core/Chip';
import Typography from '@material-ui/core/Typography';
import IconButton from '@material-ui/core/IconButton';
import { SettingsInputComponent } from '@material-ui/icons';
import { QueryRenderer } from '../../../../relay/environment';
import { monthsAgo, now } from '../../../../utils/Time';
import Theme from '../../../../components/ThemeDark';
import inject18n from '../../../../components/i18n';
import Security, { EXPLORE_EXUPDATE } from '../../../../utils/Security';

const styles = () => ({
  paper: {
    minHeight: 280,
    height: '100%',
    margin: '4px 0 0 0',
    padding: 0,
    borderRadius: 6,
  },
  paperExplore: {
    height: '100%',
    margin: 0,
    padding: 0,
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

const entityIncidentsChartIncidentsTimeSeriesQuery = graphql`
  query EntityIncidentsChartIncidentsTimeSeriesQuery(
    $objectId: String
    $field: String!
    $operation: StatsOperation!
    $startDate: DateTime!
    $endDate: DateTime!
    $interval: String!
    $relationship_type: String!
  ) {
    incidentsTimeSeries(
      objectId: $objectId
      field: $field
      operation: $operation
      startDate: $startDate
      endDate: $endDate
      interval: $interval
      relationship_type: $relationship_type
    ) {
      date
      value
    }
  }
`;

class EntityIncidentsChart extends Component {
  constructor(props) {
    super(props);
    this.state = { period: 36, interval: 2 };
  }

  changePeriod(period) {
    let interval;
    switch (period) {
      case 12:
        interval = 0;
        break;
      case 24:
        interval = 1;
        break;
      case 36:
        interval = 2;
        break;
      default:
        interval = 2;
    }
    this.setState({ period, interval });
  }

  renderContent() {
    const {
      t,
      md,
      entityId,
      // eslint-disable-next-line camelcase
      relationship_type,
      variant,
    } = this.props;
    const IncidentsTimeSeriesVariables = {
      objectId: entityId,
      field: 'first_seen',
      operation: 'count',
      startDate: monthsAgo(this.state.period),
      endDate: now(),
      interval: 'month',
      // eslint-disable-next-line camelcase
      relationship_type: relationship_type || 'targets',
    };
    return (
      <QueryRenderer
        query={entityIncidentsChartIncidentsTimeSeriesQuery}
        variables={IncidentsTimeSeriesVariables}
        render={({ props }) => {
          if (props && props.IncidentsTimeSeries) {
            return (
              <ResponsiveContainer
                height={variant === 'explore' ? '90%' : 280}
                width="100%"
              >
                <LineChart
                  data={props.IncidentsTimeSeries}
                  margin={{
                    top: 20,
                    right: 50,
                    bottom: 0,
                    left: -10,
                  }}
                >
                  <CartesianGrid strokeDasharray="2 2" stroke="#0f181f" />
                  <XAxis
                    dataKey="date"
                    stroke="#ffffff"
                    interval={this.state.interval}
                    angle={-45}
                    textAnchor="end"
                    tickFormatter={md}
                  />
                  <YAxis stroke="#ffffff" />
                  <Line
                    type="monotone"
                    stroke={Theme.palette.primary.main}
                    dataKey="value"
                  />
                </LineChart>
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
      t,
      classes,
      variant,
      title,
      configuration,
      handleOpenConfig,
    } = this.props;
    if (variant === 'explore') {
      return (
        <Paper classes={{ root: classes.paperExplore }} elevation={2}>
          <Typography
            variant="h4"
            gutterBottom={true}
            style={{ float: 'left', padding: '10px 0 0 10px' }}
          >
            {title || t('Incidents')}
          </Typography>
          <Security needs={[EXPLORE_EXUPDATE]}>
            <IconButton
              color="secondary"
              aria-label="Update"
              size="small"
              classes={{ root: classes.updateButton }}
              onClick={handleOpenConfig.bind(this, configuration)}
            >
              <SettingsInputComponent fontSize="inherit" />
            </IconButton>
          </Security>
          <div className="clearfix" />
          {this.renderContent()}
        </Paper>
      );
    }
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
          {title || t('Incidents')}
        </Typography>
        <div style={{ float: 'right', marginTop: -5 }}>
          <Chip
            classes={{ root: classes.chip }}
            style={{
              backgroundColor: this.state.period === 12 ? '#795548' : '#757575',
            }}
            label="12M"
            component="button"
            onClick={this.changePeriod.bind(this, 12)}
          />
          <Chip
            classes={{ root: classes.chip }}
            style={{
              backgroundColor: this.state.period === 24 ? '#795548' : '#757575',
            }}
            label="24M"
            component="button"
            onClick={this.changePeriod.bind(this, 24)}
          />
          <Chip
            classes={{ root: classes.chip }}
            style={{
              backgroundColor: this.state.period === 36 ? '#795548' : '#757575',
            }}
            label="36M"
            component="button"
            onClick={this.changePeriod.bind(this, 36)}
          />
        </div>
        <div className="clearfix" />
        <Paper classes={{ root: classes.paper }} elevation={2}>
          {this.renderContent()}
        </Paper>
      </div>
    );
  }
}

EntityIncidentsChart.propTypes = {
  variant: PropTypes.string,
  title: PropTypes.string,
  entityId: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
  md: PropTypes.func,
  configuration: PropTypes.object,
  handleOpenConfig: PropTypes.func,
  relationship_type: PropTypes.string,
};

export default compose(inject18n, withStyles(styles))(EntityIncidentsChart);
