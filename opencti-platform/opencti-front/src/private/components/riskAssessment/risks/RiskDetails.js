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
});

class RiskDetailsComponent extends Component {
  render() {
    const {
      t,
      classes,
      risk,
      fd,
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
                <Link
                  component="button"
                  variant="body2"
                  className={classes.link}
                  onClick={() => {
                    console.info("I'm a button.");
                  }}
                >
                  <Launch fontSize="inherit" style={{ marginRight: '5.5px' }} />{risk.installed_operating_system && t(risk.installed_operating_system.name)}
                </Link>
                {/* <ExpandableMarkdown
                  source={risk.description}
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
                {/* {risk.sophistication && t(risk.sophistication)} */}
                {risk.installed_software
                && risk.installed_software.map((software, key) => (
                  <div key={key}>
                    <div className="clearfix" />
                    <Link
                      key={key}
                      component="button"
                      variant="body2"
                      className={classes.link}
                      onClick={() => (
                        software.id && history.push(`/dashboard/risk-assessment/risks/${software.id}`)
                      )}
                    >
                      <Launch fontSize="inherit" style={{ marginRight: '5.5px' }} />{software.name && t(software.name)}
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
                {risk.motherboard_id && t(risk.motherboard_id)}
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
                {risk.ports && risk.ports.map((port, key) => (
                  port.protocols && port.protocols.map((protocol) => (
                    <Chip key={key} classes={{ root: classes.chip }} label={`${port.port_number && t(port.port_number)} ${protocol && t(protocol)}`} color="primary" />
                  ))
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
                {risk.installation_id && t(risk.installation_id)}
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
                  onClick={() => (
                    risk.connected_to_network.id && history.push(`/dashboard/risk-assessment/risks/${risk.connected_to_network.id}`)
                  )}
                >
                  <Launch fontSize="inherit" style={{ marginRight: '5.5px' }} />{risk.connected_to_network && risk.connected_to_network.name && t(risk.connected_to_network.name)}
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
                {risk.netbios_name && t(risk.netbios_name)}
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
                <Switch color="primary" defaultChecked={risk.is_virtual && risk.is_virtual} size="small" />
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
                  <Tooltip title={t('Publicly Accessible')} >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <Switch color="primary" defaultChecked={risk.is_publicly_accessible && risk.is_publicly_accessible} size="small" />
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
                {risk.fqdn && t(risk.fqdn)}
              </div>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('IPv4 Address')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                  <Tooltip title={t('ipv4_address')} >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {risk.ipv4_address
                  && risk.ipv4_address.map((ipv4Address) => (
                    <>
                      <div className="clearfix" />
                      {ipv4Address.ip_address_value && t(ipv4Address.ip_address_value)}
                    </>
                  ))}
              </div>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('IPv6 Address')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                  <Tooltip title={t('ipv6_address')} >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {risk.ipv6_address
                  && risk.ipv6_address.map((ipv6Address) => (
                    <>
                      <div className="clearfix" />
                      {ipv6Address.ip_address_value && t(ipv6Address.ip_address_value)}
                    </>
                  ))}
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
                {risk.installed_hardware && risk.installed_hardware.map((data, key) => (
                  <div key={key}>
                    <div className="clearfix" />
                      <Link
                        key={key}
                        component="button"
                        variant="body2"
                        className={classes.link}
                        onClick={() => (
                          data.id && history.push(`/dashboard/risk-assessment/risks/${data.id}`)
                        )}
                      >
                        <Launch fontSize="inherit" style={{ marginRight: '5.5px' }} />{data.name && t(data.name)}
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
                  {t('Location')}
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
                        {risk.locations && risk.locations.map((location, key) => (
                          <div key={key}>
                            {`${location.street_address && t(location.street_address)}, `}
                            {`${location.city && t(location.city)}, `}
                            {`${location.country && t(location.country)}, ${location.postal_code && t(location.postal_code)}`}
                          </div>
                        ))}
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
                {risk.model && t(risk.model)}
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
                {risk.mac_address && risk.mac_address.map((macAddress, key) => (
                  <div key={key}>
                    <div className="clearfix" />
                    {macAddress && t(macAddress)}
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
                {risk.baseline_configuration_name
                  && t(risk.baseline_configuration_name)}
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
                  <Launch fontSize="inherit" style={{ marginRight: '5.5px' }} />{risk.uri && t(risk.uri)}
                </Link>
                {/* {risk.primary_motivation
                  && t(risk.primary_motivation)} */}
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
                {risk.bios_id
                  && t(risk.bios_id)}
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
                <Switch color="primary" defaultChecked={risk.is_scanned && risk.is_scanned} size="small" />
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
                {risk.hostname
                  && t(risk.hostname)}
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
                {risk.default_gateway
                  && t(risk.default_gateway)}
              </div>
            </Grid>
          </Grid>
        </Paper>
      </div>
    );
  }
}

RiskDetailsComponent.propTypes = {
  risk: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fd: PropTypes.func,
};

const RiskDetails = createFragmentContainer(
  RiskDetailsComponent,
  {
    risk: graphql`
      fragment RiskDetails_risk on ComputingDeviceAsset {
        installed_software {
          id
          name
        }
        connected_to_network {
          id
          name
        }
        installed_operating_system {
          id
          name
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
          id
          name
          uri
        }
      }
    `,
  },
);

export default compose(inject18n, withStyles(styles))(RiskDetails);
