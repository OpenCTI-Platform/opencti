import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import { Grid, Switch, Tooltip } from '@material-ui/core';
import Chip from '@material-ui/core/Chip';
import Link from '@material-ui/core/Link';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import Launch from '@material-ui/icons/Launch';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import { BullseyeArrow, ArmFlexOutline, Information } from 'mdi-material-ui';
import ListItemText from '@material-ui/core/ListItemText';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import inject18n from '../../../../components/i18n';
import '../../../../resources/css/customScrollbar.css';

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '24px 24px 32px 24px',
    borderRadius: 6,
  },
  link: {
    fontSize: '16px',
    font: 'DIN Next LT Pro',
  },
  chip: {
    color: '#FFFFFF',
    height: 25,
    fontSize: 12,
    margin: '0 7px 7px 0',
    backgroundColor: 'rgba(6,16,45,255)',
  },
});

class DeviceDetailsComponent extends Component {
  render() {
    const {
      t, classes, device, fd,
    } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Details')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <Grid container={true} spacing={3}>
            <Grid item={true} xs={6}>
              <div style={{ marginBottom: '23px' }}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Installed Operating System')}
                </Typography>
                <div style={{ float: 'left', margin: '2px 0 0 5px' }}>
                  <Tooltip title={t('Installed Operating System')} >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <Link
                  component="button"
                  variant="body2"
                  className={classes.link}
                  onClick={() => {
                    console.info("I'm a button.");
                  }}
                >
                  <Launch fontSize="inherit" style={{ marginRight: '5.5px' }}/>{device.installed_operating_system && t(device.installed_operating_system.name)}
                </Link>
                {/* <ExpandableMarkdown
                  source={device.description}
                  limit={400}
                /> */}
              </div>
              <div style={{ marginBottom: '10px' }}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('Installed Software')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                  <Tooltip title={t('Installed Software')} >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {/* {device.sophistication && t(device.sophistication)} */}
                {device.installed_software.map((data, key) => (
                  <div key={key}>
                  <div className="clearfix" />
                  <Link
                    key={key}
                    component="button"
                    variant="body2"
                    className={classes.link}
                    onClick={() => {
                      console.info("I'm a button2.");
                    }}
                  >
                    <Launch fontSize="inherit" style={{ marginRight: '5.5px' }}/>{t(data.name)}
                  </Link>
                  </div>
                ))}
              </div>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('Motherboard ID')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                  <Tooltip title={t('Motherboard ID')} >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {device.motherboard_id && t(device.motherboard_id)}
              </div>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('Ports')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                  <Tooltip title={t('Ports')} >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {device.goals && device.goals.map((goal, key) => (
                  <Chip key={key} classes={{ root: classes.chip }} label={t(goal)} color="primary" />
                ))}
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
                {device.installation_id && t(device.installation_id)}
              </div>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('Connected to Network')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                  <Tooltip title={t('Connected to Network')} >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <Link
                  component="button"
                  variant="body2"
                  className={classes.link}
                  onClick={() => {
                    console.info("I'm a button.");
                  }}
                >
                  <Launch fontSize="inherit" style={{ marginRight: '5.5px' }}/>{t(device.connected_to_network.name)}
                </Link>
              </div>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('NetBIOS Name')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                  <Tooltip title={t('NetBIOS Name')} >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {device.netbios_name && t(device.netbios_name)}
              </div>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('Virtual')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                  <Tooltip title={t('Virtual')} >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <Switch defaultChecked={device.is_virtual} size="small" />
              </div>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('Publicly Accessible')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                  <Tooltip title={t('FQDN')} >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <Switch defaultChecked={device.is_publicly_accessible} size="small" />
              </div>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('FQDN')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                  <Tooltip title={t('FQDN')} >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {device.fqdn && t(device.fqdn)}
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
                  {t('Installed Hardware')}
                </Typography>
                <div style={{ float: 'left', margin: '2px 0 0 5px' }}>
                  <Tooltip title={t('Installed Hardware')} >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {device.installed_hardware.map((data, key) => (
                  <div key={key}>
                  <div className="clearfix" />
                  <a href={data.uri}>
                  <Link
                    to={data.uri}
                    key={key}
                    component="button"
                    variant="body2"
                    className={classes.link}
                    onClick={() => {
                      console.info("I'm a button2.");
                    }}
                  >
                    <Launch fontSize="inherit" style={{ marginRight: '5.5px' }}/>{t(data.name)}
                  </Link>
                  </a>
                  </div>
                ))}
              </div>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('Location')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                  <Tooltip title={t('Location')} >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                  <div className='scroll-bg'>
                    <div className='scroll-div'>
                      <div className='scroll-object'>
                        {[1, 2, 3, 4, 5, 6, 7, 8].map((data, key) => (
                          <>
                            {t('Lorem Ipsum Lorem Ipsum')}
                            <br></br>
                          </>
                        ))}
                      <br></br>
                    </div>
                  </div>
                </div>
              </div>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('Model')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                  <Tooltip title={t('Model')} >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {t(device.model)}
              </div>
              <div style={{ marginBottom: '15px' }}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('MAC Address')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                  <Tooltip title={t('MAC Address')} >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {device.mac_address.map((data, key) => (
                  <div key={key}>
                  <div className="clearfix" />
                    {t(data)}
                  </div>
                ))}
              </div>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('Baseline Configuration Name')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                  <Tooltip title={t('Baseline Configuration Name')} >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {device.baseline_configuration_name
                  && t(device.baseline_configuration_name)}
              </div>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('URI')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                  <Tooltip title={t('URI')} >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <Link
                  component="button"
                  variant="body2"
                  className={classes.link}
                  onClick={() => {
                    console.info("I'm a button.");
                  }}
                >
                  <Launch fontSize="inherit" style={{ marginRight: '5.5px' }}/>{t('Lorem Ipsum Lorem Ipsum')}
                </Link>
                {/* {device.primary_motivation
                  && t(device.primary_motivation)} */}
              </div>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('BIOS ID')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                  <Tooltip title={t('BIOS ID')} >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {device.bios_id
                  && t(device.bios_id)}
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
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                  <Tooltip title={t('Scanned')} >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <Switch defaultChecked={device.is_scanned} size="small" />
              </div>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('Host Name')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                  <Tooltip title={t('Host Name')} >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {device.hostname
                  && t(device.hostname)}
              </div>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('Default Gateway')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                  <Tooltip title={t('Default Gateway')} >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {device.default_gateway
                  && t(device.default_gateway)}
              </div>
              {/* <Typography
                variant="h3"
                color="textSecondary"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Secondary motivations')}
              </Typography>
              {device.secondary_motivations && (
                <List>
                  {device.secondary_motivations.map(
                    (secondaryMotivation) => (
                      <ListItem
                        key={secondaryMotivation}
                        dense={true}
                        divider={true}
                      >
                        <ListItemIcon>
                          <ArmFlexOutline />
                        </ListItemIcon>
                        <ListItemText primary={secondaryMotivation} />
                      </ListItem>
                    ),
                  )}
                </List>
              )} */}
            </Grid>
          </Grid>
        </Paper>
      </div>
    );
  }
}

DeviceDetailsComponent.propTypes = {
  device: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fd: PropTypes.func,
};

const DeviceDetails = createFragmentContainer(
  DeviceDetailsComponent,
  {
    device: graphql`
      fragment DeviceDetails_device on ComputingDeviceAsset {
        installed_software {
          name
        }
        connected_to_network {
          name
        }
        installed_operating_system {
          name
        }
        uri
        model
        mac_address
        fqdn
        network_id
        baseline_configuration_name
        bios_id
        is_scanned
        hostname
        default_gateway
        motherboard_id
        installation_id
        netbios_name
        is_virtual
        is_publicly_accessible
        installed_hardware {
          name
          uri
        }
      }
    `,
  },
);

export default compose(inject18n, withStyles(styles))(DeviceDetails);
