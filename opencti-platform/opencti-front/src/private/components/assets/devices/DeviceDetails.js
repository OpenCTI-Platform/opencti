/* eslint-disable */
/* refactor */
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
import LaunchIcon from '@material-ui/icons/Launch';
import Launch from '@material-ui/icons/Launch';
import { Information } from 'mdi-material-ui';
import inject18n from '../../../../components/i18n';

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '24px 24px 32px 24px',
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
    minWidth: 'fit-content',
  }
});

class DeviceDetailsComponent extends Component {
  render() {
    const {
      t,
      fldt,
      classes,
      device,
      history,
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
                {device?.installed_operating_system?.name
                  && <Link
                    component="button"
                    variant="body2"
                    className={classes.link}
                    onClick={() => (history.push(`/defender HQ/assets/software/${device.installed_operating_system.id}`))}
                  >
                    <Launch fontSize="inherit" style={{ marginRight: '5.5px' }} />{t(device.installed_operating_system.name)} {t(device.installed_operating_system.version || " ")}
                  </Link>}
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
                {device?.installed_hardware && device.installed_hardware.map((data, key) => (
                  <div key={key}>
                    <div className="clearfix" />
                    <Link
                      key={key}
                      component="button"
                      variant="body2"
                      className={classes.link}
                      onClick={() => (history.push(`/defender HQ/assets/devices/${data.id}`))}
                    >
                      <Launch fontSize="inherit" style={{ marginRight: '5.5px' }} />{data?.name && t(data.name)}
                    </Link>
                  </div>
                ))}
              </div>
            </Grid>
            <Grid item={true} xs={6}>
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
                <div className={classes.scrollBg}>
                  <div className={classes.scrollDiv}>
                    <div className={classes.scrollObj}>
                      {device?.installed_software
                        && device.installed_software.map((software, key) => (
                          software.name
                            && <Link
                              key={key}
                              component="button"
                              variant="body2"
                              className={classes.link}
                              onClick={() => (
                                software.id && history.push(`/defender HQ/assets/software/${software.id}`)
                              )}
                            >
                              <LaunchIcon fontSize="small"  className={classes.launchIcon} /> <div className={classes.linkTitle}>{t(software.name)} {t(software.version || " ")}</div>
                            </Link>                   
                      ))}
                    </div>
                  </div>
                </div>                
              </div>
            </Grid>
            <Grid item={true} xs={6}>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('Related Risks')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                  <Tooltip title={t('Location')}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <div className={classes.scrollBg}>
                  <div className={classes.scrollDiv}>
                    <div className={classes.scrollObj}>
                      {device?.related_risks && device.related_risks.map((risk, key) => (
                        <Link
                          key={key}
                          component="button"
                          variant="body2"
                          className={classes.link}
                          onClick={() => (history.push(`/activities/risk_assessment/risks/${risk.id}`))}
                        >
                          <LaunchIcon fontSize='small' className={classes.launchIcon}/> <div className={classes.linkTitle}>{t(risk.name)}</div>
                        </Link>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            </Grid>
            <Grid item={true} xs={6}>
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
                {device?.motherboard_id && t(device.motherboard_id)}
              </div>
            </Grid>
            <Grid item={true} xs={6}>
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
                {device?.model && t(device.model)}
              </div>
            </Grid>
            <Grid item={true} xs={6}>
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
                {device?.installation_id && t(device.installation_id)}
              </div>
            </Grid>
            <Grid item={true} xs={6}>
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
                {device?.baseline_configuration_name
                  && t(device.baseline_configuration_name)}
              </div>
            </Grid>
            <Grid item={true} xs={6}>
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
                {device?.connected_to_network?.name
                  && <Link
                    component="button"
                    variant="body2"
                    className={classes.link}
                    onClick={() => (
                      device.connected_to_network.id && history.push(`/defender HQ/assets/network/${device.connected_to_network.id}`)
                    )}
                  >
                    <Launch fontSize="inherit" style={{ marginRight: '5.5px' }} />{t(device.connected_to_network.name)}
                  </Link>}
              </div>
            </Grid>
            <Grid item={true} xs={6}>
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
                {device?.uri
                  && <Link
                    href={device?.uri}
                    variant="body2"
                    className={classes.link}
                  >
                    <Launch fontSize="inherit" style={{ marginRight: '5.5px' }} />{t(device.uri)}
                  </Link>}
              </div>
            </Grid>
            <Grid item={true} xs={6}>
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
                {device?.netbios_name && t(device.netbios_name)}
              </div>
            </Grid>
            <Grid item={true} xs={6}>
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
                {device?.bios_id
                  && t(device.bios_id)}
              </div>
            </Grid>
            <Grid item={true} xs={6}>
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
                <Switch
                  disabled
                  defaultChecked={device?.is_virtual}
                  classes={{
                    thumb: classes.thumb,
                    track: classes.switch_track,
                    switchBase: classes.switch_base,
                    colorPrimary: classes.switch_primary,
                  }}
                />
              </div>
            </Grid>
            <Grid item={true} xs={6}>
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
                  <Tooltip title={t('Publicly Accessible')} >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <Switch
                  disabled
                  defaultChecked={device?.is_publicly_accessible}
                  classes={{
                    thumb: classes.thumb,
                    track: classes.switch_track,
                    switchBase: classes.switch_base,
                    colorPrimary: classes.switch_primary,
                  }}
                />
              </div>
            </Grid>
            <Grid item={true} xs={6}>
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
                <Switch
                  disabled
                  defaultChecked={device?.is_scanned}
                  classes={{
                    thumb: classes.thumb,
                    track: classes.switch_track,
                    switchBase: classes.switch_base,
                    colorPrimary: classes.switch_primary,
                  }}
                />
              </div>
            </Grid>
            <Grid item={true} xs={6}>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('Last Scanned')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                  <Tooltip title={t('Last Scanned')} >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {device?.last_scanned && fldt(device.last_scanned)}
              </div>
            </Grid>
            <Grid item={true} xs={6}>
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
                {device?.hostname
                  && t(device.hostname)}
              </div>
            </Grid>
            <Grid item={true} xs={6}>
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
                {device?.default_gateway
                  && t(device.default_gateway)}
              </div>
            </Grid>
            <Grid item={true} xs={6}>
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
                {device?.fqdn && t(device.fqdn)}
              </div>
            </Grid>
            <Grid item={true} xs={6}>
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
                  <Tooltip title={t('CPE Identifier')} >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {device.cpe_identifier
                  && t(device.cpe_identifier)}
              </div>
            </Grid>  
            <Grid item={true} xs={6}>
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
                {device.implementation_point && t(device.implementation_point)}
              </div>
            </Grid>            
          </Grid>
          <Grid container={true} spacing={3}>
            <Grid item={true} xs={12}>
              <Typography
                variant="h3"
                color="textSecondary"
                gutterBottom={true}
                style={{ float: 'left', marginTop: 20 }}
              >
                {t('Ports')}
              </Typography>
              <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                <Tooltip title={t('Ports')}>
                  <Information fontSize="inherit" color="disabled" />
                </Tooltip>
              </div>
              <div className="clearfix" />
              <div className={classes.scrollBg}>
                <div className={classes.scrollDiv}>
                  <div className={classes.scrollObj}>
                    {device?.ports && device.ports.map((port, key) => (
                      port.protocols && port.protocols.map((protocol) => (
                        <div key={key}>
                          <div className="clearfix" />
                          {port.port_number && t(port.port_number)} {protocol && t(protocol)}
                        </div>
                      ))
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
                style={{ float: 'left', marginTop: 20 }}
              >
                {t('MAC Address')}
              </Typography>
              <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                <Tooltip title={t('MAC Address')}>
                  <Information fontSize="inherit" color="disabled" />
                </Tooltip>
              </div>
              <div className="clearfix" />
              <div className={classes.scrollBg}>
                <div className={classes.scrollDiv}>
                  <div className={classes.scrollObj}>
                    {device?.mac_address && device.mac_address.map((macAddress, key) => (
                      <div key={key}>
                        <div className="clearfix" />
                        {macAddress && t(macAddress)}
                      </div>
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
                style={{ float: 'left', marginTop: 20 }}
              >
                {t('IPv4 Address')}
              </Typography>
              <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                <Tooltip title={t('IPv4 Address')}>
                  <Information fontSize="inherit" color="disabled" />
                </Tooltip>
              </div>
              <div className="clearfix" />
              <div className={classes.scrollBg}>
                <div className={classes.scrollDiv}>
                  <div className={classes.scrollObj}>
                    {device?.ipv4_address
                      && device.ipv4_address.map((ipv4Address) => (
                        <>
                          <div className="clearfix" />
                          {ipv4Address.ip_address_value && t(ipv4Address.ip_address_value)}
                        </>
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
                style={{ float: 'left', marginTop: 20 }}
              >
                {t('IPv6 Address')}
              </Typography>
              <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                <Tooltip title={t('IPv6 Address')}>
                  <Information fontSize="inherit" color="disabled" />
                </Tooltip>
              </div>
              <div className="clearfix" />
              <div className={classes.scrollBg}>
                <div className={classes.scrollDiv}>
                  <div className={classes.scrollObj}>
                    {device?.ipv6_address
                      && device.ipv6_address.map((ipv6Address) => (
                        <>
                          <div className="clearfix" />
                          {ipv6Address.ip_address_value && t(ipv6Address.ip_address_value)}
                        </>
                      ))}
                  </div>
                </div>
              </div>
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
  fldt: PropTypes.func,
};

const DeviceDetails = createFragmentContainer(
  DeviceDetailsComponent,
  {
    device: graphql`
      fragment DeviceDetails_device on HardwareAsset {
        id
        installed_software {
          id
          name
          version
        }
        connected_to_network {
          id
          name
        }
        installed_operating_system {
          id
          name
          version
        }
        ipv4_address  {
          ip_address_value
        }
        ipv6_address  {
          ip_address_value
        }
        locations {
          city
          country
          description
        }
        ports {
          protocols
          port_number
        }
        locations{
          city
          country
          postal_code
          street_address
          administrative_area
        }
        uri
        model
        mac_address
        fqdn
        last_scanned
        cpe_identifier
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
        implementation_point
        installed_hardware {
          id
          name
          uri
        }
        related_risks {
          id
          name
        }
      }
    `,
  },
);

export default compose(inject18n, withStyles(styles))(DeviceDetails);
