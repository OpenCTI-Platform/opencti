import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
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

class RiskAnalysisThreatsComponent extends Component {
  render() {
    const {
      t,
      classes,
    } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Threats')}
        </Typography>
        <Paper className={ classes.paper } elevation={2}>

        </Paper>
      </div>
    );
  }
}

RiskAnalysisThreatsComponent.propTypes = {
  risk: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fd: PropTypes.func,
};

// const RiskAnalysisThreats = createFragmentContainer(
//   RiskAnalysisThreatsComponent,
//   {
//     risk: graphql`
//       fragment RiskAnalysisThreats_risk on ComputingDeviceAsset {
//         installed_software {
//           id
//           name
//         }
//         connected_to_network {
//           id
//           name
//         }
//         installed_operating_system {
//           id
//           name
//         }
//         ipv4_address  {
//           ip_address_value
//         }
//         ipv6_address  {
//           ip_address_value
//         }
//         locations {
//           city
//           country
//           description
//         }
//         ports {
//           protocols
//           port_number
//         }
//         locations{
//           city
//           country
//           postal_code
//           street_address
//           administrative_area
//         }
//         uri
//         model
//         mac_address
//         fqdn
//         baseline_configuration_name
//         bios_id
//         is_scanned
//         hostname
//         default_gateway
//         motherboard_id
//         installation_id
//         netbios_name
//         is_virtual
//         is_publicly_accessible
//         installed_hardware {
//           id
//           name
//           uri
//         }
//       }
//     `,
//   },
// );

export default compose(inject18n, withStyles(styles))(RiskAnalysisThreatsComponent);
