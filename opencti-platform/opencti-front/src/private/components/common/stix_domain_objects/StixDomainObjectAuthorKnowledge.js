import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql } from 'react-relay';
import CircularProgress from '@mui/material/CircularProgress';
import Card from '@mui/material/Card';
import CardContent from '@mui/material/CardContent';
import Grid from '@mui/material/Grid';
import withStyles from '@mui/styles/withStyles';
import withTheme from '@mui/styles/withTheme';
import { DescriptionOutlined, DeviceHubOutlined } from '@mui/icons-material';
import { HexagonMultipleOutline } from 'mdi-material-ui';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import Chart from 'react-apexcharts';
import { QueryRenderer } from '../../../../relay/environment';
import { monthsAgo, now, yearsAgo } from '../../../../utils/Time';
import inject18n from '../../../../components/i18n';
import ItemNumberDifference from '../../../../components/ItemNumberDifference';
import Loader from '../../../../components/Loader';
import { areaChartOptions } from '../../../../utils/Charts';
import { simpleNumberFormat } from '../../../../utils/Number';

const styles = (theme) => ({
  card: {
    width: '100%',
    marginBottom: 20,
    borderRadius: 6,
    position: 'relative',
  },
  paper: {
    margin: '10px 0 0 0',
    padding: '20px 20px 0 20px',
    borderRadius: 6,
  },
  itemIcon: {
    color: theme.palette.primary.main,
  },
  itemIconSecondary: {
    marginRight: 0,
    color: theme.palette.secondary.main,
  },
  number: {
    marginTop: 10,
    float: 'left',
    fontSize: 30,
  },
  title: {
    marginTop: 5,
    textTransform: 'uppercase',
    fontSize: 12,
    fontWeight: 500,
    color: '#a8a8a8',
  },
  icon: {
    position: 'absolute',
    color: theme.palette.primary.main,
    top: 35,
    right: 20,
  },
});

const stixDomainObjectAuthorKnowledgeReportsNumberQuery = graphql`
  query StixDomainObjectAuthorKnowledgeReportsNumberQuery(
    $authorId: String
    $endDate: DateTime
  ) {
    reportsNumber(authorId: $authorId, endDate: $endDate) {
      total
      count
    }
  }
`;

const stixDomainObjectAuthorKnowledgeStixCoreRelationshipsNumberQuery = graphql`
  query StixDomainObjectAuthorKnowledgeStixCoreRelationshipsNumberQuery(
    $type: String
    $authorId: String
    $toTypes: [String]
    $endDate: DateTime
  ) {
    stixCoreRelationshipsNumber(
      type: $type
      authorId: $authorId
      toTypes: $toTypes
      endDate: $endDate
    ) {
      total
      count
    }
  }
`;

const stixDomainObjectAuthorKnowledgeStixDomainObjectsTimeSeriesQuery = graphql`
  query StixDomainObjectAuthorKnowledgeStixDomainObjectsTimeSeriesQuery(
    $authorId: String
    $field: String!
    $operation: StatsOperation!
    $startDate: DateTime!
    $endDate: DateTime!
    $interval: String!
  ) {
    stixDomainObjectsTimeSeries(
      authorId: $authorId
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

class StixDomainObjectAuthorKnowledge extends Component {
  render() {
    const { t, fsd, n, classes, stixDomainObjectId, theme } = this.props;
    return (
      <div>
        <Grid container={true} spacing={3}>
          <Grid item={true} xs={4}>
            <Card
              variant="outlined"
              classes={{ root: classes.card }}
              style={{ height: 120 }}
            >
              <QueryRenderer
                query={stixDomainObjectAuthorKnowledgeReportsNumberQuery}
                variables={{
                  authorId: stixDomainObjectId,
                  endDate: monthsAgo(1),
                }}
                render={({ props }) => {
                  if (props && props.reportsNumber) {
                    const { total } = props.reportsNumber;
                    const difference = total - props.reportsNumber.count;
                    return (
                      <CardContent>
                        <div className={classes.title}>
                          {t('Total reports')}
                        </div>
                        <div className={classes.number}>{n(total)}</div>
                        <ItemNumberDifference difference={difference} />
                        <div className={classes.icon}>
                          <DescriptionOutlined
                            color="inherit"
                            fontSize="large"
                          />
                        </div>
                      </CardContent>
                    );
                  }
                  return (
                    <div style={{ textAlign: 'center', paddingTop: 35 }}>
                      <CircularProgress size={40} thickness={2} />
                    </div>
                  );
                }}
              />
            </Card>
          </Grid>
          <Grid item={true} xs={4}>
            <Card
              variant="outlined"
              classes={{ root: classes.card }}
              style={{ height: 120 }}
            >
              <QueryRenderer
                query={
                  stixDomainObjectAuthorKnowledgeStixCoreRelationshipsNumberQuery
                }
                variables={{
                  authorId: stixDomainObjectId,
                  toTypes: ['Stix-Cyber-Observable'],
                  endDate: monthsAgo(1),
                }}
                render={({ props }) => {
                  if (props && props.stixCoreRelationshipsNumber) {
                    const { total } = props.stixCoreRelationshipsNumber;
                    const difference = total - props.stixCoreRelationshipsNumber.count;
                    return (
                      <CardContent>
                        <div className={classes.title}>
                          {t('Total observables')}
                        </div>
                        <div className={classes.number}>{n(total)}</div>
                        <ItemNumberDifference difference={difference} />
                        <div className={classes.icon}>
                          <HexagonMultipleOutline
                            color="inherit"
                            fontSize="large"
                          />
                        </div>
                      </CardContent>
                    );
                  }
                  return (
                    <div style={{ textAlign: 'center', paddingTop: 35 }}>
                      <CircularProgress size={40} thickness={2} />
                    </div>
                  );
                }}
              />
            </Card>
          </Grid>
          <Grid item={true} xs={4}>
            <Card
              variant="outlined"
              classes={{ root: classes.card }}
              style={{ height: 120 }}
            >
              <QueryRenderer
                query={
                  stixDomainObjectAuthorKnowledgeStixCoreRelationshipsNumberQuery
                }
                variables={{
                  authorId: stixDomainObjectId,
                  endDate: monthsAgo(1),
                }}
                render={({ props }) => {
                  if (props && props.stixCoreRelationshipsNumber) {
                    const { total } = props.stixCoreRelationshipsNumber;
                    const difference = total - props.stixCoreRelationshipsNumber.count;
                    return (
                      <CardContent>
                        <div className={classes.title}>
                          {t('Total relations')}
                        </div>
                        <div className={classes.number}>{n(total)}</div>
                        <ItemNumberDifference difference={difference} />
                        <div className={classes.icon}>
                          <DeviceHubOutlined color="inherit" fontSize="large" />
                        </div>
                      </CardContent>
                    );
                  }
                  return (
                    <div style={{ textAlign: 'center', paddingTop: 35 }}>
                      <CircularProgress size={40} thickness={2} />
                    </div>
                  );
                }}
              />
            </Card>
          </Grid>
        </Grid>
        <Grid container={true} spacing={3} style={{ marginBottom: 20 }}>
          <Grid item={true} xs={12}>
            <Typography variant="h4" gutterBottom={true}>
              {t('Created entities')}
            </Typography>
            <Paper
              classes={{ root: classes.paper }}
              variant="outlined"
              style={{ height: 300 }}
            >
              <QueryRenderer
                query={
                  stixDomainObjectAuthorKnowledgeStixDomainObjectsTimeSeriesQuery
                }
                variables={{
                  authorId: stixDomainObjectId,
                  field: 'created_at',
                  operation: 'count',
                  startDate: yearsAgo(1),
                  endDate: now(),
                  interval: 'month',
                }}
                render={({ props }) => {
                  if (props && props.stixDomainObjectsTimeSeries) {
                    const chartData = props.stixDomainObjectsTimeSeries.map(
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
                            name: t('Number of reports'),
                            data: chartData,
                          },
                        ]}
                        type="area"
                        width="100%"
                        height="100%"
                      />
                    );
                  }
                  return <Loader variant="inElement" />;
                }}
              />
            </Paper>
          </Grid>
        </Grid>
      </div>
    );
  }
}

StixDomainObjectAuthorKnowledge.propTypes = {
  stixDomainObjectId: PropTypes.string,
  stixDomainObjectType: PropTypes.string,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withTheme,
  withStyles(styles),
)(StixDomainObjectAuthorKnowledge);
