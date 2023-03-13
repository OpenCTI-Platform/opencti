/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import LinearProgress from '@material-ui/core/LinearProgress';
import Typography from '@material-ui/core/Typography';
import { Grid, Chip, Box } from '@material-ui/core';
import inject18n from '../../../../../components/i18n';
import { QueryRenderer } from '../../../../../relay/environment';

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '24px 24px 0 24px',
    borderRadius: 6,
  },
  chip: {
    color: theme.palette.header.text,
    height: 25,
    fontSize: 12,
    padding: '14px 12px',
    margin: '0 7px 7px 0',
    backgroundColor: theme.palette.header.background,
  },
});

const dataSourceWorksQuery = graphql`
  query DataSourceWorksQuery($id: ID!, $since: DateTime) {
    dataSource(id: $id) {
      activities (since: $since) {
        id
        entity_type
        created
        modified
        source
        status
        start_time
        completed_time
        total_operations
        operations_completed
      }
    }
  }
`;

class DataSourceWorksComponent extends Component {

  render() {
    const {
      t,
      classes,
      dataSourceId,
      fldt,
    } = this.props;
    return (
      <QueryRenderer
        query={dataSourceWorksQuery}
        variables={{ id: dataSourceId, since: '2023-01-01T00:00:00Z' }}
        render={({ error, props }) => {
          if (error) {
            console.error(error);
            toastGenericError('Failed to get Data Source data');
          }
          if (props) {
            if (props.dataSource) {
              const activities = props.dataSource.activities;
              return activities.map((activity) => (
                <>
                  <Grid item xs={12} style={{ marginTop: 20 }}>
                    <Typography variant="h4" gutterBottom={true}>
                      {t('In Progress Works')}
                    </Typography>
                    <Paper classes={{ root: classes.paper }} elevation={2}>
                      <Grid container>
                        <Grid container xs={6}>
                          <Grid item xs={6}>
                            <div>
                              <Typography
                                variant="h3"
                                color="textSecondary"
                                gutterBottom={true}
                              >
                                {t('Name')}
                              </Typography>
                              <div className="clearfix" />
                              {activity.name && t(activity.name)}
                            </div>
                          </Grid>
                          <Grid item xs={6}>
                            <div>
                              <Typography
                                variant="h3"
                                color="textSecondary"
                                gutterBottom={true}
                              >
                                {t('Status')}
                              </Typography>
                              <div className="clearfix" />
                              <Chip
                                variant="outlined"
                                label={activity.status}
                                style={{ backgroundColor: 'rgba(73, 184, 252, 0.2)' }}
                                classes={{ root: classes.chip }}
                              />
                            </div>
                          </Grid>
                          <Grid item xs={6}>
                            <div style={{ marginTop: '20px' }}>
                              <Typography
                                variant="h3"
                                color="textSecondary"
                                gutterBottom={true}
                              >
                                {t('Work start time')}
                              </Typography>
                              <div className="clearfix" />
                              {activity.created && fldt(activity.created)}
                            </div>
                          </Grid>
                          <Grid item xs={6}>
                            <div style={{ marginTop: '20px' }}>
                              <Typography
                                variant="h3"
                                color="textSecondary"
                                gutterBottom={true}
                              >
                                {t('Work end time')}
                              </Typography>
                              <div className="clearfix" />
                              {activity.modified && fldt(activity.modified)}
                            </div>
                          </Grid>
                        </Grid>
                        <Grid container xs={6}>
                          <Grid item xs={6}>
                            <div>
                              <Typography
                                variant="h3"
                                color="textSecondary"
                                gutterBottom={true}
                              >
                                {t('Operations Completed')}
                              </Typography>
                              <div className="clearfix" />
                              {activity.operations_completed && t(activity.operations_completed)}
                            </div>
                          </Grid>
                          <Grid item xs={6}>
                            <div>
                              <Typography
                                variant="h3"
                                color="textSecondary"
                                gutterBottom={true}
                              >
                                {t('Total Number of Operations')}
                              </Typography>
                              <div className="clearfix" />
                              {activity.total_operations && t(activity.total_operations)}
                            </div>
                          </Grid>
                        </Grid>
                      </Grid>
                    </Paper>
                  </Grid>
                  {activity.status === 'completed' && (
                    <Grid item xs={12} style={{ marginTop: 20 }}>
                      <Typography variant="h4" gutterBottom={true}>
                        {t('Completed Works')}
                      </Typography>
                      <Paper classes={{ root: classes.paper }} elevation={2}>
                        <Grid container>
                          <Grid container xs={6}>
                            <Grid item xs={6}>
                              <div>
                                <Typography
                                  variant="h3"
                                  color="textSecondary"
                                  gutterBottom={true}
                                >
                                  {t('Name')}
                                </Typography>
                                <div className="clearfix" />
                                {activity.name && t(activity.name)}
                              </div>
                            </Grid>
                            <Grid item xs={6}>
                              <div>
                                <Typography
                                  variant="h3"
                                  color="textSecondary"
                                  gutterBottom={true}
                                >
                                  {t('Status')}
                                </Typography>
                                <div className="clearfix" />
                                <Chip
                                  variant="outlined"
                                  label={activity.status}
                                  style={{ backgroundColor: 'rgba(64, 204, 77, 0.2)' }}
                                  classes={{ root: classes.chip }}
                                />
                              </div>
                            </Grid>
                            <Grid item xs={6}>
                              <div style={{ marginTop: '20px' }}>
                                <Typography
                                  variant="h3"
                                  color="textSecondary"
                                  gutterBottom={true}
                                >
                                  {t('Work start time')}
                                </Typography>
                                <div className="clearfix" />
                                {activity.created && fldt(activity.created)}
                              </div>
                            </Grid>
                            <Grid item xs={6}>
                              <div style={{ marginTop: '20px' }}>
                                <Typography
                                  variant="h3"
                                  color="textSecondary"
                                  gutterBottom={true}
                                >
                                  {t('Work end time')}
                                </Typography>
                                <div className="clearfix" />
                                {activity.modified && fldt(activity.modified)}
                              </div>
                            </Grid>
                          </Grid>
                          <Grid container xs={6}>
                            <Grid item xs={6}>
                              <div>
                                <Typography
                                  variant="h3"
                                  color="textSecondary"
                                  gutterBottom={true}
                                >
                                  {t('Operations Completed')}
                                </Typography>
                                <div className="clearfix" />
                                {activity.operations_completed && t(activity.operations_completed)}
                              </div>
                            </Grid>
                            <Grid item xs={6}>
                              <div>
                                <Typography
                                  variant="h3"
                                  color="textSecondary"
                                  gutterBottom={true}
                                >
                                  {t('Total Number of Operations')}
                                </Typography>
                                <div className="clearfix" />
                                {activity.total_operations && t(activity.total_operations)}
                              </div>
                            </Grid>
                            {/* <Grid item xs={12}>
                              <Box sx={{ display: 'flex', alignItems: 'center' }}>
                                <Box sx={{ width: '100%', mr: 1 }}>
                                  <LinearProgress value={100} variant="determinate" style={{ height: 10, borderRadius: 5 }} />
                                </Box>
                                <Box sx={{ minWidth: 35 }}>
                                  <Typography variant="body2" color="text.secondary">{t('100%')}</Typography>
                                </Box>
                              </Box>
                            </Grid> */}
                          </Grid>
                        </Grid>
                      </Paper>
                    </Grid>
                  )}
                </>
              ))
            }
          }
        }}
      />
    );
  }
}

DataSourceWorksComponent.propTypes = {
  dataSourceId: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  fldt: PropTypes.func,
};

export default compose(inject18n, withStyles(styles))(DataSourceWorksComponent);
