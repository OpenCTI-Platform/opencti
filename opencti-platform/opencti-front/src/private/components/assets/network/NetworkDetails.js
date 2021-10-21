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
import List from '@material-ui/core/List';
import { Formik, Form, Field } from 'formik';
import Switch from '@material-ui/core/Switch';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import {
  BullseyeArrow,
  ArmFlexOutline,
  Information,
} from 'mdi-material-ui';
import ListItemText from '@material-ui/core/ListItemText';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import inject18n from '../../../../components/i18n';
import NetworkLocations from './NetworkLocations';

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
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
});

class NetworkDetailsComponent extends Component {
  render() {
    const {
      t, classes, network, fd,
    } = this.props;
    const ntadr = network.network_address_range;
    const startingAddress = ntadr.starting_ip_address && ntadr.starting_ip_address.ip_address_value;
    const endingAddress = ntadr.ending_ip_address && ntadr.ending_ip_address.ip_address_value;
    console.log('this is a network', network);
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
                  {t('Network Name')}
                </Typography>
                <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                  <Tooltip title={t('Network Name')} >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {t(network.network_name)}
              </div>
              <div>
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
                  <Tooltip title={t('Starting Address')} >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <Switch defaultChecked={false} inputProps={{ 'aria-label': 'ant design' }} />
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
                  {t('Network ID')}
                </Typography>
                <div style={{ float: 'left', margin: '-5px 0 0 5px' }}>
                  <Tooltip title={t('Network ID')} >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {t(network.network_id)}
              </div>
              <div>
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
                {t(network.implementation_point)}
              </div>
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

// const NetworkDetails = createFragmentContainer(
//   NetworkDetailsComponent,
//   {
//     network: graphql`
//       fragment NetworkDetails_network on IntrusionSet {
//         id
//         first_seen
//         last_seen
//         description
//         resource_level
//         primary_motivation
//         secondary_motivations
//         goals
//         ...NetworkLocations_network
//       }
//     `,
//   },
// );

const NetworkDetails = createFragmentContainer(
  NetworkDetailsComponent,
  {
    network: graphql`
      fragment NetworkDetails_network on NetworkAsset {
        network_name
        network_id
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
