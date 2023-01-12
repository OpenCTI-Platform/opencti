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
import LinearProgress from '@material-ui/core/LinearProgress';
import Typography from '@material-ui/core/Typography';
import { Button, Grid, Chip, Box } from '@material-ui/core';
import Markdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import rehypeRaw from 'rehype-raw';
import remarkParse from 'remark-parse';
import inject18n from '../../../../../components/i18n';
import DataSourceInformationExchangePolicyPopover from './DataSourceInformationExchangePolicyPopover';
import DataSourceConfigurationPopover from './DataSourceConfigurationPopover';

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
  chip: {
    color: theme.palette.header.text,
    height: 25,
    fontSize: 12,
    padding: '14px 12px',
    margin: '0 7px 7px 0',
    backgroundColor: theme.palette.header.background,
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
  markingText: {
    background: theme.palette.header.text,
    color: 'black',
    width: '100px',
    textAlign: 'center',
    padding: '3px 0',
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
      openInformationExchangePolicy: false,
      openConfiguration: false,
    };
  }

  handleOpenConfiguration() {
    this.setState({ openConfiguration: true });
  }

  handleCloseConfiguration() {
    this.setState({ openConfiguration: false });
  }

  handleOpenInformationExchangePolicy() {
    this.setState({ openInformationExchangePolicy: true });
  }

  handleCloseInformationExchangePolicy() {
    this.setState({ openInformationExchangePolicy: false });
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
                    {dataSource.name && t(dataSource.name)}
                  </div>
                </Grid>
                <Grid item xs={6}>
                  <div>
                    <Typography
                      variant="h3"
                      color="textSecondary"
                      gutterBottom={true}
                    >
                      {t('ID')}
                    </Typography>
                    <div className="clearfix" />
                    {dataSource.id && t(dataSource.id)}
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
                    <Chip variant="outlined" label="EXTERNAL_IMPORT" style={{ backgroundColor: 'rgba(211, 19, 74, 0.2)' }} classes={{ root: classes.chip }} />
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
                <Grid item xs={12}>
                  <div style={{ marginTop: '20px' }}>
                    <Typography
                      variant="h3"
                      color="textSecondary"
                      gutterBottom={true}
                    >
                      {t('Total Entities Collected')}
                    </Typography>
                    <div className="clearfix" />
                    {t('184,501')}
                  </div>
                </Grid>
                <Grid item={true} xs={12}>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                  >
                    {t('State')}
                  </Typography>
                  <div className="clearfix" />
                  <div className={classes.scrollBg}>
                    <div className={classes.scrollDiv}>
                      <div className={classes.scrollObj}>
                      </div>
                    </div>
                  </div>
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
                      {t('Configuration')}
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
                      {t('Information Exchange Policy')}
                    </Button>
                  </div>
                </Grid>
              </Grid>
            </Paper>
          </Grid>
        </Grid>
        <Grid container spacing={1}>
          <Grid item xs={12}>
            <div style={{ marginTop: '3%' }}>
              <Typography variant="h4" gutterBottom={true}>
                {t('In Progress Works')}
              </Typography>
            </div>
            <Paper classes={{ root: classes.paper }} elevation={2}>
              <Grid container>
                <Grid container item xs={6}>
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
                      {dataSource.name && t(dataSource.name)}
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
                      <Chip variant="outlined" label="In Progress" style={{ backgroundColor: 'rgba(73, 184, 252, 0.2)' }} classes={{ root: classes.chip }} />
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
                        {t('Work end time')}
                      </Typography>
                      <div className="clearfix" />
                    </div>
                  </Grid>
                </Grid>
                <Grid container item xs={6}>
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
                      {t('0')}
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
                      {t('0')}
                    </div>
                  </Grid>
                  <Grid item xs={12}>
                    <Box sx={{ display: 'flex', alignItems: 'center' }}>
                      <Box sx={{ width: '100%', mr: 1 }}>
                        <LinearProgress value={60} variant="determinate" style={{ height: 10, borderRadius: 5 }} />
                      </Box>
                      <Box sx={{ minWidth: 35 }}>
                        <Typography variant="body2" color="text.secondary">{t('60%')}</Typography>
                      </Box>
                    </Box>
                  </Grid>
                </Grid>
              </Grid>
            </Paper>
          </Grid>
          <Grid item xs={12}>
            <div style={{ marginTop: '6%' }}>
              <Typography variant="h4" gutterBottom={true}>
                {t('Completed Works')}
              </Typography>
            </div>
            <Paper classes={{ root: classes.paper }} elevation={2}>
              <Grid container>
                <Grid container item xs={6}>
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
                      {dataSource.name && t(dataSource.name)}
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
                      <Chip variant="outlined" label="Completed" style={{ backgroundColor: 'rgba(64, 204, 77, 0.2)' }} classes={{ root: classes.chip }} />
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
                        {t('Work end time')}
                      </Typography>
                      <div className="clearfix" />
                    </div>
                  </Grid>
                </Grid>
                <Grid container item xs={6}>
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
                      {t('0')}
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
                      {t('0')}
                    </div>
                  </Grid>
                  <Grid item xs={12}>
                    <Box sx={{ display: 'flex', alignItems: 'center' }}>
                      <Box sx={{ width: '100%', mr: 1 }}>
                        <LinearProgress value={100} variant="determinate" style={{ height: 10, borderRadius: 5 }} />
                      </Box>
                      <Box sx={{ minWidth: 35 }}>
                        <Typography variant="body2" color="text.secondary">{t('100%')}</Typography>
                      </Box>
                    </Box>
                  </Grid>
                </Grid>
              </Grid>
            </Paper>
          </Grid>
        </Grid>
        {/* <DataSourceConfigurationPopover
          openConfiguration={this.state.openConfiguration}
          handleCloseConfiguration={this.handleCloseConfiguration.bind(this)}
        />
        <DataSourceInformationExchangePolicyPopover
          openInformationExchangePolicy={this.state.openInformationExchangePolicy}
          handleCloseInformationExchangePolicy={this.handleCloseInformationExchangePolicy.bind(this)}
        /> */}
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
      }
    `,
  },
);

export default compose(inject18n, withStyles(styles))(DataSourceDetails);
