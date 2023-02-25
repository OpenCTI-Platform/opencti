/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Tooltip from '@material-ui/core/Tooltip';
import Paper from '@material-ui/core/Paper';
import { Information } from 'mdi-material-ui';
import Typography from '@material-ui/core/Typography';
import Grid from '@material-ui/core/Grid';
import Link from '@material-ui/core/Link';
import Switch from '@material-ui/core/Switch';
import LaunchIcon from '@material-ui/icons/Launch';
import inject18n from '../../../../components/i18n';
import ResponsiblePartiesPopover from './ResponsiblePartiesPopover'

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '24px 24px 32px 24px',
    borderRadius: 6,
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
    height: '78px',
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
  thumb: {
    '&.MuiSwitch-thumb': {
      color: 'white',
    },
  },
  switch_track: {
    backgroundColor: '#D3134A !important',
    opacity: '1 !important',
  },
  switch_base: {
    color: 'white',
    '&.Mui-checked + .MuiSwitch-track': {
      backgroundColor: '#49B8FC !important',
      opacity: 1,
    },
  },
});

class InformationSystemOverviewComponent extends Component {
  render() {
    const {
      t, classes, informationSystem, fldt, history
    } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Basic Information')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <Grid container={true} spacing={3}>
            <Grid item={true} xs={12}>
              <div className={classes.textBase}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ margin: 0 }}
                >
                  {t('Id')}
                </Typography>
                <Tooltip title={t('Id')} >
                  <Information style={{ marginLeft: '5px' }} fontSize="inherit" color="disabled" />
                </Tooltip>
              </div>
              <div className="clearfix" />
              {informationSystem.id && t(informationSystem.id)}
            </Grid>
            <Grid item={true} xs={6}>
              <div className={classes.textBase}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ margin: 0 }}
                >
                  {t('Created')}
                </Typography>
                <Tooltip
                  title={t('Created')}>
                  <Information style={{ marginLeft: '5px' }} fontSize="inherit" color="disabled" />
                </Tooltip>
              </div>
              <div className="clearfix" />
              {informationSystem.created && fldt(informationSystem.created)}
            </Grid>
            <Grid item={true} xs={6}>
              <div className={classes.textBase}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ margin: 0 }}
                >
                  {t('Modified')}
                </Typography>
                <Tooltip title={t('Modified')} >
                  <Information style={{ marginLeft: '5px' }} fontSize="inherit" color="disabled" />
                </Tooltip>
              </div>
              <div className="clearfix" />
              {informationSystem.modified && fldt(informationSystem.modified)}
            </Grid>
            <Grid item={true} xs={12}>
              <div className={classes.textBase}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ margin: 0 }}
                >
                  {t('Description')}
                </Typography>
                <Tooltip title={t('Description')} >
                  <Information style={{ marginLeft: '5px' }} fontSize="inherit" color="disabled" />
                </Tooltip>
              </div>
              <div className="clearfix" />
              <div className={classes.scrollBg}>
                <div className={classes.scrollDiv}>
                  <div className={classes.scrollObj}>
                    {informationSystem?.description &&
                      t(informationSystem.description)}
                  </div>
                </div>
              </div>
            </Grid>
            <Grid item={true} xs={6}>
              <div className={classes.textBase}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ margin: 0 }}
                >
                  {t('Short Name')}
                </Typography>
                <Tooltip title={t('Short Name')} >
                  <Information style={{ marginLeft: '5px' }} fontSize="inherit" color="disabled" />
                </Tooltip>
              </div>
              <div className="clearfix" />
              {informationSystem.short_name && t(informationSystem.short_name)}
            </Grid>
            <Grid item={true} xs={6}>
              <div className={classes.textBase}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ margin: 0 }}
                >
                  {t('Date Authorized')}
                </Typography>
                <Tooltip title={t('Date Authorized')} >
                  <Information style={{ marginLeft: '5px' }} fontSize="inherit" color="disabled" />
                </Tooltip>
              </div>
              <div className="clearfix" />
              {informationSystem.date_authorized && fldt(informationSystem.date_authorized)}
            </Grid>
            <Grid item={true} xs={6}>
              <div className={classes.textBase}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ margin: 0 }}
                >
                  {t('Status')}
                </Typography>
                <Tooltip title={t('Status')} >
                  <Information style={{ marginLeft: '5px' }} fontSize="inherit" color="disabled" />
                </Tooltip>
              </div>
              <div className="clearfix" />
              {informationSystem.operational_status && t(informationSystem.operational_status)}
            </Grid>
            <Grid item={true} xs={6}>
              <div className={classes.textBase}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ margin: 0 }}
                >
                  {t('Privacy Sensitive System')}
                </Typography>
                <Tooltip title={t('Privacy Sensitive System')} >
                  <Information style={{ marginLeft: '5px' }} fontSize="inherit" color="disabled" />
                </Tooltip>
              </div>
              <div className="clearfix" />
              <div style={{ display: 'flex', alignItems: 'center' }}>
                <Typography>No</Typography>
                <Switch
                  disabled
                  defaultChecked={informationSystem?.privacy_designation}
                  classes={{
                    thumb: classes.thumb,
                    track: classes.switch_track,
                    switchBase: classes.switch_base,
                    colorPrimary: classes.switch_primary,
                  }}
                />
                <Typography>No</Typography>
              </div>                
            </Grid>
            <Grid item={true} xs={6}>
              <div className={classes.textBase}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ margin: 0 }}
                >
                  {t('Deployment Model')}
                </Typography>
                <Tooltip title={t('Deployment Model')} >
                  <Information style={{ marginLeft: '5px' }} fontSize="inherit" color="disabled" />
                </Tooltip>
              </div>
              <div className="clearfix" />
              {informationSystem.deployment_model && t(informationSystem.deployment_model)}
            </Grid>
            <Grid item={true} xs={6}>
              <div className={classes.textBase}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ margin: 0 }}
                >
                  {t('Cloud Service Model')}
                </Typography>
                <Tooltip title={t('Cloud Service Model')} >
                  <Information style={{ marginLeft: '5px' }} fontSize="inherit" color="disabled" />
                </Tooltip>
              </div>
              <div className="clearfix" />
              {informationSystem.cloud_service_model && t(informationSystem.cloud_service_model)}
            </Grid>
            <Grid item={true} xs={6}>
              <div className={classes.textBase}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ margin: 0 }}
                >
                  {t('Identity Assurance Level')}
                </Typography>
                <Tooltip title={t('Identity Assurance Level')} >
                  <Information style={{ marginLeft: '5px' }} fontSize="inherit" color="disabled" />
                </Tooltip>
              </div>
              <div className="clearfix" />
              {informationSystem.identity_assurance_level && t(informationSystem.identity_assurance_level)}
            </Grid>
            <Grid item={true} xs={6}>
              <div className={classes.textBase}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ margin: 0 }}
                >
                  {t('Authenticator Assurance Level')}
                </Typography>
                <Tooltip title={t('Authenticator Assurance Level')} >
                  <Information style={{ marginLeft: '5px' }} fontSize="inherit" color="disabled" />
                </Tooltip>
              </div>
              <div className="clearfix" />
              {informationSystem.authenticator_assurance_level && t(informationSystem.authenticator_assurance_level)}
            </Grid>
            <Grid item={true} xs={12}>
              <div className={classes.textBase}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ margin: 0 }}
                >
                  {t('Federation Assurance Level')}
                </Typography>
                <Tooltip title={t('Federation Assurance Level')} >
                  <Information style={{ marginLeft: '5px' }} fontSize="inherit" color="disabled" />
                </Tooltip>
              </div>
              <div className="clearfix" />
              {informationSystem.federation_assurance_level && t(informationSystem.federation_assurance_level)}
            </Grid>
            <Grid item={true} xs={12}>
              <ResponsiblePartiesPopover name={'responsible_parties'} responsibleParties={informationSystem.responsible_parties}/>
            </Grid>
          </Grid>
        </Paper>
      </div>
    );
  }
}

InformationSystemOverviewComponent.propTypes = {
  informationSystem: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

const InformationSystemOverview = createFragmentContainer(InformationSystemOverviewComponent, {
  informationSystem: graphql`
    fragment InformationSystemOverview_information on InformationSystem {
      id
      created
      modified
      description
      short_name
      date_authorized
      operational_status
      privacy_designation
      deployment_model
      cloud_service_model
      identity_assurance_level
      authenticator_assurance_level
      federation_assurance_level
      responsible_parties {
        id
      }
    }
  `,
});

export default compose(inject18n, withStyles(styles))(InformationSystemOverview);
