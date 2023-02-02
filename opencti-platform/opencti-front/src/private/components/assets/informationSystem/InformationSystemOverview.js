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
import LaunchIcon from '@material-ui/icons/Launch';
import inject18n from '../../../../components/i18n';
import Switch from '@material-ui/core/Switch';

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
  link: {
    textAlign: 'left',
    fontSize: '1rem',
    display: 'flex',
    minWidth: '50px',
    width: '100%',
  },
  launchIcon: {
    marginRight: '5%',
  },
  linkTitle: {
    color: '#fff',
  }
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
              <Typography
                variant="h3"
                color="textSecondary"
                gutterBottom={true}
                style={{ float: 'left' }}
              >
                {t('Id')}
              </Typography>
              <div style={{ float: 'left', margin: '-5px 0 0 5px' }}>
                <Tooltip title={t('Id')} >
                  <Information fontSize="inherit" color="disabled" />
                </Tooltip>
              </div>
              <div className="clearfix" />
              {informationSystem.ids && t(informationSystem.ids)}
            </Grid>
            <Grid item={true} xs={6}>
              <Typography
                variant="h3"
                color="textSecondary"
                gutterBottom={true}
                style={{ float: 'left' }}
              >
                {t('Created')}
              </Typography>
              <div style={{ float: 'left', margin: '-5px 0 0 5px' }}>
                <Tooltip
                  title={t('Created')}>
                  <Information fontSize="inherit" color="disabled" />
                </Tooltip>
              </div>
              <div className="clearfix" />
              {/* {informationSystem.cpe_identifier && t(informationSystem.cpe_identifier)} */}
            </Grid>
            <Grid item={true} xs={6}>
              <Typography
                variant="h3"
                color="textSecondary"
                gutterBottom={true}
                style={{ float: 'left' }}
              >
                {t('Modified')}
              </Typography>
              <div style={{ float: 'left', margin: '-5px 0 0 5px' }}>
                <Tooltip title={t('Modified')} >
                  <Information fontSize="inherit" color="disabled" />
                </Tooltip>
              </div>
              <div className="clearfix" />
              {/* {informationSystem.implementation_point && t(informationSystem.implementation_point)} */}
            </Grid>
            <Grid item={true} xs={12}>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: "left", marginTop: 20 }}
                >
                  {t("Description")}
                </Typography>
                <div style={{ float: "left", margin: "21px 0 0 5px" }}>
                  <Tooltip title={t("Description")}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <div className={classes.scrollBg}>
                  <div className={classes.scrollDiv}>
                    <div className={classes.scrollObj}>
                      {/* {cyioDomainObject?.description &&
                        t(cyioDomainObject.description)} */}
                    </div>
                  </div>
                </div>
              </div>
            </Grid>
            <Grid item={true} xs={6}>
              <Typography
                variant="h3"
                color="textSecondary"
                gutterBottom={true}
                style={{ float: 'left' }}
              >
                {t('Short Name')}
              </Typography>
              <div style={{ float: 'left', margin: '-5px 0 0 5px' }}>
                <Tooltip title={t('Short Name')} >
                  <Information fontSize="inherit" color="disabled" />
                </Tooltip>
              </div>
              <div className="clearfix" />
              {/* {informationSystem.license_key && t(informationSystem.license_key)} */}
            </Grid>
            <Grid item={true} xs={6}>
              <Typography
                variant="h3"
                color="textSecondary"
                gutterBottom={true}
                style={{ float: 'left' }}
              >
                {t('Date Authorized')}
              </Typography>
              <div style={{ float: 'left', margin: '-5px 0 0 5px' }}>
                <Tooltip title={t('Date Authorized')} >
                  <Information fontSize="inherit" color="disabled" />
                </Tooltip>
              </div>
              <div className="clearfix" />
              {/* {informationSystem.installation_id && t(informationSystem.installation_id)} */}
            </Grid>
            <Grid item={true} xs={6}>
              <Typography
                variant="h3"
                color="textSecondary"
                gutterBottom={true}
                style={{ float: 'left' }}
              >
                {t('Status')}
              </Typography>
              <div style={{ float: 'left', margin: '-5px 0 0 5px' }}>
                <Tooltip title={t('Status')} >
                  <Information fontSize="inherit" color="disabled" />
                </Tooltip>
              </div>
              <div className="clearfix" />
              {/* {informationSystem.installation_id && t(informationSystem.installation_id)} */}
            </Grid>
            <Grid item={true} xs={6}>
              <Typography
                variant="h3"
                color="textSecondary"
                gutterBottom={true}
                style={{ float: 'left' }}
              >
                {t('Privacy Sensitive System')}
              </Typography>
              <div style={{ float: 'left', margin: '-5px 0 0 5px' }}>
                <Tooltip title={t('Privacy Sensitive System')} >
                  <Information fontSize="inherit" color="disabled" />
                </Tooltip>
              </div>
              <div className="clearfix" />
              {/* {informationSystem.installation_id && t(informationSystem.installation_id)} */}
            </Grid>
            <Grid item={true} xs={6}>
              <Typography
                variant="h3"
                color="textSecondary"
                gutterBottom={true}
                style={{ float: 'left' }}
              >
                {t('Deployment Model')}
              </Typography>
              <div style={{ float: 'left', margin: '-5px 0 0 5px' }}>
                <Tooltip title={t('Deployment Model')} >
                  <Information fontSize="inherit" color="disabled" />
                </Tooltip>
              </div>
              <div className="clearfix" />
              {/* {informationSystem.installation_id && t(informationSystem.installation_id)} */}
            </Grid>
            <Grid item={true} xs={6}>
              <Typography
                variant="h3"
                color="textSecondary"
                gutterBottom={true}
                style={{ float: 'left' }}
              >
                {t('Cloud Service Model')}
              </Typography>
              <div style={{ float: 'left', margin: '-5px 0 0 5px' }}>
                <Tooltip title={t('Cloud Service Model')} >
                  <Information fontSize="inherit" color="disabled" />
                </Tooltip>
              </div>
              <div className="clearfix" />
              {/* {informationSystem.installation_id && t(informationSystem.installation_id)} */}
            </Grid>
            <Grid item={true} xs={6}>
              <Typography
                variant="h3"
                color="textSecondary"
                gutterBottom={true}
                style={{ float: 'left' }}
              >
                {t('Identity Assurance Level')}
              </Typography>
              <div style={{ float: 'left', margin: '-5px 0 0 5px' }}>
                <Tooltip title={t('Identity Assurance Level')} >
                  <Information fontSize="inherit" color="disabled" />
                </Tooltip>
              </div>
              <div className="clearfix" />
              {/* {informationSystem.installation_id && t(informationSystem.installation_id)} */}
            </Grid>
            <Grid item={true} xs={6}>
              <Typography
                variant="h3"
                color="textSecondary"
                gutterBottom={true}
                style={{ float: 'left' }}
              >
                {t('Authenticator Assurance Level')}
              </Typography>
              <div style={{ float: 'left', margin: '-5px 0 0 5px' }}>
                <Tooltip title={t('Authenticator Assurance Level')} >
                  <Information fontSize="inherit" color="disabled" />
                </Tooltip>
              </div>
              <div className="clearfix" />
              {/* {informationSystem.installation_id && t(informationSystem.installation_id)} */}
            </Grid>
            <Grid item={true} xs={12}>
              <Typography
                variant="h3"
                color="textSecondary"
                gutterBottom={true}
                style={{ float: 'left' }}
              >
                {t('Federation Assurance Level')}
              </Typography>
              <div style={{ float: 'left', margin: '-5px 0 0 5px' }}>
                <Tooltip title={t('Federation Assurance Level')} >
                  <Information fontSize="inherit" color="disabled" />
                </Tooltip>
              </div>
              <div className="clearfix" />
              {/* {informationSystem.installation_id && t(informationSystem.installation_id)} */}
            </Grid>
            <Grid item={true} xs={12}>
              <Typography
                variant="h3"
                color="textSecondary"
                gutterBottom={true}
                style={{ float: 'left' }}
              >
                {t('Responsible Parties')}
              </Typography>
              <div style={{ float: 'left', margin: '-5px 0 0 5px' }}>
                <Tooltip title={t('Responsible Parties')} >
                  <Information fontSize="inherit" color="disabled" />
                </Tooltip>
              </div>
              <div className="clearfix" />
              <div className={classes.scrollBg}>
                <div className={classes.scrollDiv}>
                  <div className={classes.scrollObj}>
                    {/* {cyioDomainObject?.description &&
                      t(cyioDomainObject.description)} */}
                  </div>
                </div>
              </div>
            </Grid>
            {/* Labels field pending below */}
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
    fragment InformationSystemOverview_information on SoftwareAsset {
      id
      software_identifier
      license_key
      cpe_identifier
      patch_level
      installation_id
      implementation_point
      last_scanned
      is_scanned
      installed_on {
        id
        entity_type
        vendor_name
        name
        version
      }
      related_risks {
        id
        name
      }
    }
  `,
});

export default compose(inject18n, withStyles(styles))(InformationSystemOverview);
