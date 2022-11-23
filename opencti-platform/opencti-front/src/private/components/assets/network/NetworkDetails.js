/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Tooltip from '@material-ui/core/Tooltip';
import Typography from '@material-ui/core/Typography';
import Grid from '@material-ui/core/Grid';
import Switch from '@material-ui/core/Switch';
import LaunchIcon from '@material-ui/icons/Launch';
import { Link } from '@material-ui/core';
import { Information } from 'mdi-material-ui';
import inject18n from '../../../../components/i18n';

const arr = [
  {name: '123.234'},
  {name: '123.23412'},
  {name: '123.23423'},
  {name: '123.23445'},
  {name: '123.23421345'},
  {name: '123.234567'},
]

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '24px 24px 32px 24px',
    borderRadius: 6,
  },
  chip: {
    fontSize: 12,
    lineHeight: '12px',
    backgroundColor: theme.palette.background.chip,
    borderRadius: 5,
    color: '#ffffff',
    textTransform: 'uppercase',
    margin: '0 5px 5px 0',
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
    fontSize: '16px',
    display: 'flex',
  },
  launchIcon: {
    marginRight: '5%',
  },
  linkTitle: {
    color: '#fff',
  }
});

class NetworkDetailsComponent extends Component {
  render() {
    const { t, classes, network,fldt, history } = this.props;
    const ntadr = network.network_address_range;
    const startingAddress = ntadr?.starting_ip_address && ntadr.starting_ip_address?.ip_address_value;
    const endingAddress = ntadr?.ending_ip_address && ntadr.ending_ip_address?.ip_address_value;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Details')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <Grid container={true} spacing={3}>
            <Grid container spacing={3}>
              <Grid item={true} xs={6}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Network Name')}
                </Typography>
                <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                  <Tooltip title={t('Network Name')} >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {network.network_name && t(network.network_name)}
              </Grid>
              <Grid item={true} xs={6}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Network ID')}
                </Typography>
                <div style={{ float: 'left', margin: '-5px 0 0 5px' }}>
                  <Tooltip title={t('Network ID')} >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {network.network_id && t(network.network_id)}
              </Grid>
            </Grid>
            <Grid container spacing={3}>
              <Grid item={true} xs={6}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('Starting Address')}
                </Typography>
                <div style={{ float: 'left', margin: '20px 0 0 5px' }}>
                  <Tooltip title={t('Starting Address')} >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                  { startingAddress }
              </Grid>            
              <Grid item={true} xs={6}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('Ending Address')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                  <Tooltip title={t('Ending Address')} >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                { endingAddress }
              </Grid>       
            </Grid>
            <Grid container spacing={3}>              
              <Grid item={true} xs={6}>
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
                {network.implementation_point && t(network.implementation_point)}
              </Grid>
            </Grid>
            <Grid container spacing={3}>
              <Grid item={true} xs={6}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('Scanned')}
                </Typography>
                <div style={{ float: 'left', margin: '20px 0 0 5px' }}>
                  <Tooltip title={t('Starting Address')} >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <Switch disabled defaultChecked={network?.is_scanned} inputProps={{ 'aria-label': 'ant design' }} />
              </Grid>       
              <Grid item={true} xs={6}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20  }}
                >
                  {t('Last Scanned')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                  <Tooltip title={t('Last Scanned')} >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {network.last_scanned && fldt(network.last_scanned)}
              </Grid>             
            </Grid>
            <Grid container spacing={3}>
              <Grid item={true} xs={6}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('Connected Devices')}
                </Typography>
                <div className="clearfix" />
                <div className={classes.scrollBg}>
                  <div className={classes.scrollDiv}>
                    <div className={classes.scrollObj}>
                      {arr && arr.map((arr, key) => (
                        <Link
                          key={key}
                          component="button"
                          variant="body2"
                          className={classes.link}
                          onClick={() => (history.push(`/defender HQ/assets/software/2fc46e04-9046-5c3e-b8ea-f8c905858d06`))}
                        >
                          <LaunchIcon fontSize='small' className={classes.launchIcon}/> <div className={classes.linkTitle}>{t(arr.name)}</div>
                        </Link>
                      ))}
                    </div>
                  </div>
                </div>
              </Grid>       
              <Grid item={true} xs={6}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20  }}
                >
                  {t('Related Risks')}
                </Typography>
                <div className="clearfix" />
                <div className={classes.scrollBg}>
                  <div className={classes.scrollDiv}>
                    <div className={classes.scrollObj}>
                      {arr && arr.map((arr, key) => (
                      <Link
                        key={key}
                        component="button"
                        variant="body2"
                        className={classes.link}
                        onClick={() => (history.push(`/defender HQ/assets/software/2fc46e04-9046-5c3e-b8ea-f8c905858d06`))}
                      >
                        <LaunchIcon fontSize='small' className={classes.launchIcon}/> <div className={classes.linkTitle}>{t(arr.name)}</div>
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

NetworkDetailsComponent.propTypes = {
  network: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fd: PropTypes.func,
};

const NetworkDetails = createFragmentContainer(
  NetworkDetailsComponent,
  {
    network: graphql`
      fragment NetworkDetails_network on NetworkAsset {
        network_name
        network_id
        is_scanned
        last_scanned
        implementation_point
        network_address_range {
          ending_ip_address{
            ... on IpV4Address {
              ip_address_value
            }
          }
          starting_ip_address{
            ... on IpV4Address {
              ip_address_value
            }
          }
        }
      }
    `,
  },
);

export default compose(inject18n, withStyles(styles))(NetworkDetails);
