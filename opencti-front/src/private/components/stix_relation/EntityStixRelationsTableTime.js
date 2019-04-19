import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, reverse } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import Table from '@material-ui/core/Table';
import TableBody from '@material-ui/core/TableBody';
import TableCell from '@material-ui/core/TableCell';
import TableHead from '@material-ui/core/TableHead';
import TableRow from '@material-ui/core/TableRow';
import Chip from '@material-ui/core/Chip';
import { withStyles } from '@material-ui/core/styles';
import CircularProgress from '@material-ui/core/CircularProgress';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import { QueryRenderer } from '../../../relay/environment';
import inject18n from '../../../components/i18n';
import { monthsAgo, now } from '../../../utils/Time';

const styles = theme => ({
  paper: {
    minHeight: 340,
    height: '100%',
    margin: '4px 0 0 0',
    padding: 0,
    backgroundColor: theme.palette.paper.background,
    color: theme.palette.text.main,
    borderRadius: 6,
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
});

const entityStixRelationsTableTimeStixRelationTimeSeriesQuery = graphql`
  query EntityStixRelationsTableTimeStixRelationTimeSeriesQuery(
    $fromId: String
    $entityTypes: [String]
    $relationType: String
    $resolveInferences: Boolean
    $resolveRelationType: String
    $resolveRelationRole: String
    $resolveRelationToTypes: [String]
    $resolveViaTypes: [EntityRelation]
    $toTypes: [String]
    $field: String!
    $operation: StatsOperation!
    $startDate: DateTime!
    $endDate: DateTime!
    $interval: String!
  ) {
    stixRelationsTimeSeries(
      fromId: $fromId
      entityTypes: $entityTypes
      relationType: $relationType
      resolveInferences: $resolveInferences
      resolveRelationType: $resolveRelationType
      resolveRelationRole: $resolveRelationRole
      resolveRelationToTypes: $resolveRelationToTypes
      resolveViaTypes: $resolveViaTypes
      toTypes: $toTypes
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

class EntityStixRelationsTableTime extends Component {
  constructor(props) {
    super(props);
    this.state = { interval: 'year' };
  }

  changeInterval(interval) {
    this.setState({ interval });
  }

  render() {
    const {
      t,
      md,
      yd,
      classes,
      entityId,
      toTypes,
      relationType,
      title,
      resolveInferences,
      entityTypes,
      resolveRelationType,
      resolveRelationRole,
      resolveRelationToTypes,
      resolveViaTypes,
    } = this.props;
    const startDate = this.state.interval === 'month' ? monthsAgo(6) : monthsAgo(12 * 5);
    const stixRelationsTimeSeriesVariables = {
      fromId: entityId || null,
      entityTypes: entityTypes || null,
      relationType,
      toTypes: toTypes || null,
      field: 'first_seen',
      operation: 'count',
      startDate,
      endDate: now(),
      interval: this.state.interval,
      resolveInferences,
      resolveRelationType,
      resolveRelationRole,
      resolveRelationToTypes,
      resolveViaTypes,
    };
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
          {title ? t(title) : t(`relation_${relationType}`)}
        </Typography>
        <div style={{ float: 'right', marginTop: -6 }}>
          <Chip
            classes={{ root: classes.chip }}
            style={{
              backgroundColor:
                this.state.interval === 'month' ? '#795548' : '#757575',
            }}
            label={t('Month')}
            component="button"
            onClick={this.changeInterval.bind(this, 'month')}
          />
          <Chip
            classes={{ root: classes.chip }}
            style={{
              backgroundColor:
                this.state.interval === 'year' ? '#795548' : '#757575',
            }}
            label={t('Year')}
            component="button"
            onClick={this.changeInterval.bind(this, 'year')}
          />
        </div>
        <div className="clearfix" />
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <QueryRenderer
            query={entityStixRelationsTableTimeStixRelationTimeSeriesQuery}
            variables={stixRelationsTimeSeriesVariables}
            render={({ props }) => {
              if (
                props
                && props.stixRelationsTimeSeries
                && props.stixRelationsTimeSeries.length > 0
              ) {
                const stixRelationsTimeSeries = reverse(
                  props.stixRelationsTimeSeries,
                );
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
                        <TableCell align="right">{`${t('Number of')} ${t(
                          `relation_${relationType}`,
                        )}s`}</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {stixRelationsTimeSeries.map((row) => {
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

EntityStixRelationsTableTime.propTypes = {
  entityId: PropTypes.string,
  relationType: PropTypes.string,
  resolveInferences: PropTypes.bool,
  resolveRelationType: PropTypes.string,
  resolveRelationRole: PropTypes.string,
  resolveRelationToTypes: PropTypes.array,
  resolveViaTypes: PropTypes.array,
  entityTypes: PropTypes.array,
  title: PropTypes.string,
  toTypes: PropTypes.array,
  classes: PropTypes.object,
  t: PropTypes.func,
  md: PropTypes.func,
  yd: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(EntityStixRelationsTableTime);
