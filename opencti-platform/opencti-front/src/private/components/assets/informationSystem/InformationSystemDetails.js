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

class InformationSystemDetailsComponent extends Component {
  render() {
    const {
       t, classes, informationSystem,fldt, history
    } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Details')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <Grid container={true} spacing={3}>
            <Grid container spacing={3} style={{marginBottom: "20px"}}>
              <Grid item={true} xs={6}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Software Identifier')}
                </Typography>
                <div style={{ float: 'left', margin: '-5px 0 0 5px' }}>
                  <Tooltip title={t('Software Identifier')} >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {informationSystem.software_identifier && t(informationSystem.software_identifier)}
              </Grid>              
            </Grid>
            <Grid container spacing={3} style={{marginBottom: "20px"}}>
              <Grid item={true} xs={6}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('CPE Identifier')}
                </Typography>
                <div style={{ float: 'left', margin: '-5px 0 0 5px' }}>
                  <Tooltip
                    title={t('CPE Identifier')}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />                
                  {informationSystem.cpe_identifier && t(informationSystem.cpe_identifier)}               
              </Grid>
              <Grid item={true} xs={6}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Implementation Point')}
                </Typography>
                <div style={{ float: 'left', margin: '-5px 0 0 5px' }}>
                  <Tooltip title={t('Implementation Point')} >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {informationSystem.implementation_point && t(informationSystem.implementation_point)}
              </Grid>                        
            </Grid>
            <Grid container spacing={3} style={{marginBottom: "20px"}}>
              <Grid item={true} xs={6}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('License Key')}
                </Typography>
                <div style={{ float: 'left', margin: '-5px 0 0 5px' }}>
                  <Tooltip title={t('License Key')} >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {informationSystem.license_key && t(informationSystem.license_key)}
              </Grid>              
              <Grid item={true} xs={6}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Installation ID')}
                </Typography>
                <div style={{ float: 'left', margin: '-5px 0 0 5px' }}>
                  <Tooltip title={t('Installation ID')} >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {informationSystem.installation_id && t(informationSystem.installation_id)}
              </Grid>
            </Grid>
            <Grid container spacing={3} style={{marginBottom: "20px"}}>
              <Grid item={true} xs={6}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Scanned')}
                </Typography>
                <div style={{ float: 'left', margin: '-5px 0 0 5px' }}>
                  <Tooltip title={t('Scanned')} >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <Switch disabled defaultChecked={informationSystem?.is_scanned} inputProps={{ 'aria-label': 'ant design' }} />
              </Grid>    
              <Grid item={true} xs={6}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Last Scanned')}
                </Typography>
                <div style={{ float: 'left', margin: '-5px 0 0 5px' }}>
                  <Tooltip
                    title={t('Last Scanned')}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {informationSystem.last_scanned && fldt(informationSystem.last_scanned)}
              </Grid>
            </Grid>
            <Grid container spacing={1}>
              <Grid item={true} xs={12}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Installed on Assets')}
                </Typography>
                <div className="clearfix" />
                <div className={classes.scrollBg}>
                  <div className={classes.scrollDiv}>
                    <div className={classes.scrollObj}>
                      {informationSystem.installed_on && informationSystem.installed_on.map((asset, key) => (
                        <Link
                          key={key}
                          component="button"
                          variant="body2"
                          className={classes.link}
                          onClick={() => (history.push(`/defender HQ/assets/devices/${asset.id}`))}
                        >
                          <LaunchIcon fontSize='small' className={classes.launchIcon}/><div className={classes.linkTitle}>{t(asset.name)}</div>
                        </Link>
                      ))}
                    </div>
                  </div>
                </div>
              </Grid>       
              <Grid item={true} xs={12}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left'  }}
                >
                  {t('Related Risks')}
                </Typography>
                <div className="clearfix" />
                <div className={classes.scrollBg}>
                  <div className={classes.scrollDiv}>
                    <div className={classes.scrollObj}>
                      {informationSystem.related_risks && informationSystem.related_risks.map((risk, key) => (
                      <Link
                        key={key}
                        component="button"
                        variant="body2"
                        className={classes.link}
                        onClick={() => (history.push(`/activities/risk_assessment/risks/${risk.id}`))}
                      >
                        <LaunchIcon fontSize='small' className={classes.launchIcon}/><div className={classes.linkTitle}>{t(risk.name)}</div>
                      </Link>
                      ))}
                    </div>
                  </div>
                </div>
              </Grid>             
            </Grid>
          </Grid>
        </Paper>
      </div>
    );
  }
}

InformationSystemDetailsComponent.propTypes = {
  informationSystem: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

const InformationSystemDetails = createFragmentContainer(InformationSystemDetailsComponent, {
  informationSystem: graphql`
    fragment InformationSystemDetails_information on SoftwareAsset {
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

export default compose(inject18n, withStyles(styles))(InformationSystemDetails);
