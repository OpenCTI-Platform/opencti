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
import inject18n from '../../../../components/i18n';
import Switch from '@material-ui/core/Switch';

const styles = () => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '24px 24px 32px 24px',
    borderRadius: 6,
  },
});

class SoftwareDetailsComponent extends Component {
  render() {
    const {
      fld, t, classes, software,
    } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Details')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <Grid container={true} spacing={3}>
            <Grid item={true} xs={6}>
              <div>
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
                {software.software_identifier && t(software.software_identifier)}
              </div>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('License Key')}
                </Typography>
                <div style={{ float: 'left', margin: '15px 0 0 5px' }}>
                  <Tooltip title={t('License Key')} >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {software.license_key && t(software.license_key)}
              </div>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('CPE Identifier')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                  <Tooltip
                    title={t('CPE Identifier')}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {software.cpe_identifier && t(software.cpe_identifier)}
              </div>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('Scanned')}
                </Typography>
                <div style={{ float: 'left', margin: '20px 0 0 5px' }}>
                  <Tooltip title={t('Scanned')} >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <Switch disabled defaultChecked={software?.is_scanned} inputProps={{ 'aria-label': 'ant design' }} />
              </div>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Last Scanned')}
                </Typography>
                <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                  <Tooltip
                    title={t('Last Scanned')}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {software.last_scanned && t(software.last_scanned)}
              </div>
            </Grid>
            <Grid item={true} xs={6}>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Patch Level')}
                </Typography>
                <div style={{ float: 'left', margin: '-5px 0 0 5px' }}>
                  <Tooltip title={t('Patch Level')} >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {software.patch_level && t(software.patch_level)}
              </div>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('Installation ID')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                  <Tooltip title={t('Installation ID')} >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {software.installation_id && t(software.installation_id)}
              </div>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('Implementation Point')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                  <Tooltip title={t('Implementation Point')} >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {software.implementation_point && t(software.implementation_point)}
              </div>
            </Grid>
          </Grid>
        </Paper>
      </div>
    );
  }
}

SoftwareDetailsComponent.propTypes = {
  software: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

const SoftwareDetails = createFragmentContainer(SoftwareDetailsComponent, {
  software: graphql`
    fragment SoftwareDetails_software on SoftwareAsset {
      id
      software_identifier
      license_key
      cpe_identifier
      patch_level
      installation_id
      implementation_point
      last_scanned
      is_scanned
    }
  `,
});

export default compose(inject18n, withStyles(styles))(SoftwareDetails);
