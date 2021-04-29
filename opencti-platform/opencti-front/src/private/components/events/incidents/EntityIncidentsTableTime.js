import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, reverse } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import CircularProgress from '@material-ui/core/CircularProgress';
import Paper from '@material-ui/core/Paper';
import Chip from '@material-ui/core/Chip';
import Table from '@material-ui/core/Table';
import TableBody from '@material-ui/core/TableBody';
import TableCell from '@material-ui/core/TableCell';
import TableHead from '@material-ui/core/TableHead';
import TableRow from '@material-ui/core/TableRow';
import Typography from '@material-ui/core/Typography';
import IconButton from '@material-ui/core/IconButton';
import { SettingsInputComponent } from '@material-ui/icons';
import { QueryRenderer } from '../../../../relay/environment';
import { monthsAgo, now } from '../../../../utils/Time';
import inject18n from '../../../../components/i18n';
import Security, { EXPLORE_EXUPDATE } from '../../../../utils/Security';

const styles = () => ({
  paper: {
    minHeight: 340,
    height: '100%',
    margin: '4px 0 0 0',
    padding: 0,
    borderRadius: 6,
    overflow: 'hidden',
  },
  paperExplore: {
    height: '100%',
    margin: 0,
    padding: '0 0 10px 0',
    borderRadius: 6,
    overflow: 'hidden',
  },
  tableHead: {
    textTransform: 'uppercase',
    height: 40,
    fontSize: 11,
  },
  tableBody: {
    fontSize: 15,
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

const entityIncidentsTableTimeIncidentsTimeSeriesQuery = graphql`
  query EntityIncidentsTableTimeIncidentsTimeSeriesQuery(
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

class EntityIncidentsTableTime extends Component {
  constructor(props) {
    super(props);
    this.state = { interval: 'year' };
  }

  changeInterval(interval) {
    this.setState({ interval });
  }

  renderContent() {
    const {
      t,
      md,
      yd,
      entityId,
      // eslint-disable-next-line camelcase
      relationship_type,
      variant,
      classes,
      startDate,
      endDate,
    } = this.props;
    const monthInterval = this.state.interval === 'month' ? monthsAgo(6) : monthsAgo(12 * 5);
    const finalStartDate = variant === 'explore' && startDate ? startDate : monthInterval;
    const IncidentsTimeSeriesVariables = {
      objectId: entityId,
      field: 'first_seen',
      operation: 'count',
      startDate: finalStartDate,
      endDate: variant === 'explore' && endDate ? endDate : now(),
      interval: this.state.interval,
      // eslint-disable-next-line camelcase
      relationship_type: relationship_type || 'targets',
    };
    return (
      <QueryRenderer
        query={entityIncidentsTableTimeIncidentsTimeSeriesQuery}
        variables={IncidentsTimeSeriesVariables}
        render={({ props }) => {
          if (
            props
            && props.IncidentsTimeSeries
            && props.IncidentsTimeSeries.length > 0
          ) {
            const IncidentsTimeSeries = reverse(props.IncidentsTimeSeries);
            return (
              <Table className={classes.table}>
                <TableHead>
                  <TableRow className={classes.tableHead}>
                    <TableCell>
                      {t(
                        this.state.interval.charAt(0).toUpperCase()
                          + this.state.interval.slice(1),
                      )}
                    </TableCell>
                    <TableCell align="right">
                      {t('Number of incidents')}
                    </TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {IncidentsTimeSeries.map((row) => {
                    let date;
                    if (this.state.interval === 'month') {
                      date = md(row.date);
                    } else if (this.state.interval === 'year') {
                      date = yd(row.date);
                    }
                    return (
                      <TableRow key={row.date} hover={true}>
                        <TableCell
                          component="th"
                          scope="row"
                          padding="dense"
                          className={classes.tableBody}
                        >
                          {date}
                        </TableCell>
                        <TableCell
                          align="right"
                          padding="dense"
                          className={classes.tableBody}
                        >
                          {row.value}
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
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

EntityIncidentsTableTime.propTypes = {
  variant: PropTypes.string,
  title: PropTypes.string,
  entityId: PropTypes.string,
  startDate: PropTypes.string,
  endDate: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
  md: PropTypes.func,
  yd: PropTypes.func,
  configuration: PropTypes.object,
  handleOpenConfig: PropTypes.func,
  relationship_type: PropTypes.string,
};

export default compose(inject18n, withStyles(styles))(EntityIncidentsTableTime);
