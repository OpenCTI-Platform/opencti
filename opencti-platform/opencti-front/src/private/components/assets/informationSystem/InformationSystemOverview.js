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
import ResponsiblePartiesField from '../../common/form/ResponsiblePartiesField';

const styles = (theme) => ({
  paper: {
    height: '100%',
    maxHeight: '850px',
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
                <Tooltip title={t('An ID (Identifier) is a unique value used to identify a record')} >
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
                  title={t('The date and time when the object was first created or instantiated.')}>
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
                <Tooltip title={t('The date and time when the object was last changed or modified.')} >
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
                <Tooltip title={t('The description is used to provide a human-readable explanation or summary of the object, its purpose, and its properties.')} >
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
                <Tooltip title={t('Identifies a short name for the system, such as an acronym, that is suitable for display in a data table or summary list.')} >
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
                <Tooltip title={t('Identifies the date the system received its authorization.')} >
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
                <Tooltip title={t('Indicates the operational status of the information system.')} >
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
                <Tooltip title={t('Identifies whether this a privacy sensitive system.')} >
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
                <Tooltip title={t('Identifies the deployment model for the information system.')} >
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
                <Tooltip title={t('Identifies the type of the cloud service model.')} >
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
                <Tooltip title={t('Identifies a category that conveys the degree of confidence that the applicant\'s claimed identity is their real identity as defined by NIST SP 800-63-3.')} >
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
                <Tooltip title={t('Identifies a category describing the strength of the authentication process as defined by NIST SP 800-63-3.')} >
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
                <Tooltip title={t('Identifies a category describing the assertion protocol used by the federation to communicate authentication and attribute information (if applicable) to an relying party (RP) as defined by NIST SP 800-63-3.')} >
                  <Information style={{ marginLeft: '5px' }} fontSize="inherit" color="disabled" />
                </Tooltip>
              </div>
              <div className="clearfix" />
              {informationSystem.federation_assurance_level && t(informationSystem.federation_assurance_level)}
            </Grid>
            <Grid item={true} xs={12}>
            <ResponsiblePartiesField                   
              id={informationSystem.id}
              fromType={informationSystem.__typename}
              toType='OscalResponsibleParty'
              name='responsible_parties'
              title='Responsible Parties'
            />
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
      __typename
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
        name
      }
    }
  `,
});

export default compose(inject18n, withStyles(styles))(InformationSystemOverview);
