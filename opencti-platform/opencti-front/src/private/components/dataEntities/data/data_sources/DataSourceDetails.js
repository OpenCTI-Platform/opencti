/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import {
  CogOutline,
} from 'mdi-material-ui';
import LaunchIcon from '@material-ui/icons/Launch';
import Typography from '@material-ui/core/Typography';
import { Button, Grid, Chip, Tooltip } from '@material-ui/core';
import Markdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { Information } from 'mdi-material-ui';
import rehypeRaw from 'rehype-raw';
import remarkParse from 'remark-parse';
import inject18n from '../../../../../components/i18n';
import DataSourceWorks from './DataSourceWorks';
import DataSourceConnectionPopover from './DataSourceConnectionPopover';
import DataSourceDataUsageRestrictionsPopover from './DataSourceDataUsageRestrictionsPopover';

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '24px 24px 0 24px',
    borderRadius: 6,
  },
  link: {
    textAlign: 'left',
    fontSize: '16px',
    font: 'DIN Next LT Pro',
  },
  scrollBg: {
    background: theme.palette.header.background,
    width: '100%',
    color: 'white',
    padding: '10px 5px 10px 15px',
    borderRadius: '5px',
    lineHeight: '20px',
  },
  scrollDiv: {
    width: '100%',
    background: theme.palette.header.background,
    height: '130px',
    overflow: 'hidden',
    overflowY: 'scroll',
  },
  scrollObj: {
    color: theme.palette.header.text,
    fontFamily: 'sans-serif',
    padding: '0px',
    textAlign: 'left',
  },
  textBase: {
    display: 'flex',
    alignItems: 'center',
    marginBottom: 5,
  },
  circleBorderBtn: {
    borderRadius: '1.8rem',
    margin: '0 5px 10px 0',
  },
  chip: { borderRadius: '4px' }
});

class DataSourceDetailsComponent extends Component {

  constructor(props) {
    super(props);
    this.state = {
      openDataUsageRestrictions: false,
      openConnection: false,
    };
  }

  handleOpenConfiguration() {
    this.setState({ openConnection: true });
  }

  handleCloseConnection() {
    this.setState({ openConnection: false });
  }

  handleOpenInformationExchangePolicy() {
    this.setState({ openDataUsageRestrictions: true });
  }

  handleCloseDataUsageRestrictions() {
    this.setState({ openDataUsageRestrictions: false });
  }

  render() {
    const {
      t,
      classes,
      refreshQuery,
      dataSource,
      fldt,
      history,
    } = this.props;
    return (
      <div style={{ height: '100%', marginBottom: '5%' }}>
        <Grid container={true} spacing={3}>
          <Grid item xs={6}>
            <Typography variant="h4" gutterBottom={true}>
              {t('Basic Information')}
            </Typography>
            <Paper classes={{ root: classes.paper }} elevation={2}>
              <Grid container item xs={12} spacing={1}>
                <Grid item xs={12}>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                  >
                    {t('ID')}
                  </Typography>
                  <div className="clearfix" />
                  {dataSource.id && t(dataSource.id)}
                </Grid>
              </Grid>
              <Grid container item xs={12} spacing={1}>
                <Grid item xs={6}>
                  <div style={{ marginTop: '20px' }}>
                    <Typography
                      variant="h3"
                      color="textSecondary"
                      gutterBottom={true}
                    >
                      {t('Created')}
                    </Typography>
                    <div className="clearfix" />
                    {dataSource.created && fldt(dataSource.created)}
                  </div>
                </Grid>
                <Grid item xs={6}>
                  <div style={{ marginTop: '20px' }}>
                    <Typography
                      variant="h3"
                      color="textSecondary"
                      gutterBottom={true}
                    >
                      {t('Last Modified')}
                    </Typography>
                    <div className="clearfix" />
                    {dataSource.modified && fldt(dataSource.modified)}
                  </div>
                </Grid>
              </Grid>
              <Grid container item xs={12} spacing={1}>
                <Grid item xs={6}>
                  <div style={{ marginTop: '20px' }}>
                    <Typography
                      variant="h3"
                      color="textSecondary"
                      gutterBottom={true}
                    >
                      {t('Only Contextual')}
                    </Typography>
                    <div className="clearfix" />
                    {(dataSource && dataSource.contextual === true) && (
                      <Button style={{ width: '40%' }} color="primary" variant="contained">Yes</Button>
                    )}
                    {(dataSource && dataSource.contextual === false) && (
                      <Button style={{ width: '40%' }} color="primary" variant="contained">No</Button>
                    )}
                  </div>
                </Grid>
                <Grid item xs={6}>
                  <div style={{ marginTop: '20px' }}>
                    <Typography
                      variant="h3"
                      color="textSecondary"
                      gutterBottom={true}
                    >
                      {t('Automatic Trigger')}
                    </Typography>
                    <div className="clearfix" />
                    {(dataSource && dataSource.auto === true) && (
                      <Button style={{ width: '40%' }} color="primary" variant="contained">Yes</Button>
                    )}
                    {(dataSource && dataSource.auto === false) && (
                      <Button style={{ width: '40%' }} color="primary" variant="contained">No</Button>
                    )}
                  </div>
                </Grid>
              </Grid>
              <Grid container item xs={12} spacing={1}>
                <Grid item xs={6}>
                  <div style={{ marginTop: '20px' }}>
                    <Typography
                      variant="h3"
                      color="textSecondary"
                      gutterBottom={true}
                    >
                      {t('Scope')}
                    </Typography>
                    <div className="clearfix" />
                    {dataSource.scope.length && dataSource.scope.map((scope, i) => (
                      <Button key={i} className={classes.circleBorderBtn} color="primary" variant="contained">{scope}</Button>
                    ))}
                  </div>
                </Grid>
                <Grid item xs={6}>
                  <div style={{ marginTop: '20px' }}>
                    <Typography
                      variant="h3"
                      color="textSecondary"
                      gutterBottom={true}
                    >
                      {t('Type')}
                    </Typography>
                    <div className="clearfix" />
                    <Chip variant="outlined" label={dataSource.entity_type} style={{ backgroundColor: 'rgba(211, 19, 74, 0.2)' }} classes={{ root: classes.chip }} />
                  </div>
                </Grid>
                <Grid item={true} xs={12}>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                  >
                    {t('Description')}
                  </Typography>
                  <div className="clearfix" />
                  <div className={classes.scrollBg}>
                    <div className={classes.scrollDiv}>
                      <div className={classes.scrollObj}>
                        <Markdown
                          remarkPlugins={[remarkGfm, remarkParse]}
                          rehypePlugins={[rehypeRaw]}
                          parserOptions={{ commonmark: true }}
                          className="markdown"
                        >
                          {dataSource.description && t(dataSource.description)}
                        </Markdown>
                      </div>
                    </div>
                  </div>
                </Grid>
              </Grid>
            </Paper>
          </Grid>
          <Grid item xs={6}>
            <Typography variant="h4" gutterBottom={true}>
              {t('Details')}
            </Typography>
            <Paper classes={{ root: classes.paper }} elevation={2}>
              <Grid container item xs={12} spacing={1}>
                <Grid item xs={6}>
                  <div className={classes.textBase}>
                    <Typography
                      variant="h3"
                      color="textSecondary"
                      gutterBottom={true}
                      style={{ margin: 0 }}
                    >
                      {t('Every')}
                    </Typography>
                    <Tooltip
                      title={t(
                        'Every',
                      )}
                    >
                      <Information style={{ marginLeft: '5px' }} fontSize="inherit" color="disabled" />
                    </Tooltip>
                  </div>
                  <div className="clearfix" />
                  {dataSource.update_frequency && t(dataSource.update_frequency.period)}
                </Grid>
                <Grid item xs={6}>
                  <div className={classes.textBase}>
                    <Typography
                      variant="h3"
                      color="textSecondary"
                      gutterBottom={true}
                      style={{ margin: 0 }}
                    >
                      {t('Update Frequency')}
                    </Typography>
                    <Tooltip
                      title={t(
                        'Update Frequency',
                      )}
                    >
                      <Information style={{ marginLeft: '5px' }} fontSize="inherit" color="disabled" />
                    </Tooltip>
                  </div>
                  <div className="clearfix" />
                  {dataSource.update_frequency && t(dataSource.update_frequency.unit)}
                </Grid>
                <Grid item xs={6}>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                    style={{ margin: 0 }}
                  >
                    {t('Total Entities Collected')}
                  </Typography>
                  <div className="clearfix" />

                </Grid>
                <Grid item xs={6}>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                  >
                    {t('Last Successful Run')}
                  </Typography>
                  <div className="clearfix" />

                </Grid>
              </Grid>
              <Grid container item xs={12}>
                <Grid item={true} xs={4}>
                  <div style={{ marginTop: '20px' }}>
                    <Button
                      color='primary'
                      variant='contained'
                      startIcon={<CogOutline />}
                      sx={{ mr: 5 }}
                      onClick={this.handleOpenConfiguration.bind(this)}
                    >
                      {t('Connection Info')}
                    </Button>
                  </div>
                </Grid>
                <Grid item={true} xs={8}>
                  <div style={{ marginTop: '20px' }}>
                    <Button
                      color='primary'
                      variant='contained'
                      startIcon={<LaunchIcon />}
                      onClick={this.handleOpenInformationExchangePolicy.bind(this)}
                    >
                      {t('Data Usage Restrictions')}
                    </Button>
                  </div>
                </Grid>
              </Grid>
            </Paper>
          </Grid>
          <DataSourceWorks
            dataSourceId={dataSource.id}
          />
        </Grid>
        <DataSourceConnectionPopover
          dataSource={dataSource}
          openConnection={this.state.openConnection}
          handleCloseConnection={this.handleCloseConnection.bind(this)}
        />
        <DataSourceDataUsageRestrictionsPopover
          dataSource={dataSource}
          refreshQuery={refreshQuery}
          openDataUsageRestrictions={this.state.openDataUsageRestrictions}
          handleCloseDataUsageRestrictions={this.handleCloseDataUsageRestrictions.bind(this)}
        />
      </div>
    );
  }
}

DataSourceDetailsComponent.propTypes = {
  dataSource: PropTypes.object,
  classes: PropTypes.object,
  refreshQuery: PropTypes.func,
  t: PropTypes.func,
  fldt: PropTypes.func,
};

const DataSourceDetails = createFragmentContainer(
  DataSourceDetailsComponent,
  {
    dataSource: graphql`
      fragment DataSourceDetails_data on DataSource {
        __typename
        id
        auto
        name
        scope
        created
        modified
        contextual
        description
        entity_type
        update_frequency {
          period
          unit
        }
        ...DataSourceConnectionPopover_data
        ...DataSourceDataUsageRestrictionsPopover_dataSource
      }
    `,
  },
);

export default compose(inject18n, withStyles(styles))(DataSourceDetails);
