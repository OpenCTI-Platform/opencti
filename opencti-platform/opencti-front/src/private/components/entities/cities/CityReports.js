import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import inject18n from '../../../../components/i18n';
import CityPopover from './CityPopover';
import Reports from '../../reports/Reports';
import StixDomainEntityHeader from '../../common/stix_domain_entities/StixDomainEntityHeader';

const styles = () => ({
  container: {
    margin: 0,
  },
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '5px 0 0 0',
    padding: '25px 15px 15px 15px',
    borderRadius: 6,
  },
});

class CityReportsComponent extends Component {
  render() {
    const { classes, city } = this.props;
    return (
      <div className={classes.container}>
        <StixDomainEntityHeader
          stixDomainEntity={city}
          PopoverComponent={<CityPopover />}
        />
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <Reports objectId={city.id} />
        </Paper>
      </div>
    );
  }
}

CityReportsComponent.propTypes = {
  city: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const CityReports = createFragmentContainer(CityReportsComponent, {
  city: graphql`
    fragment CityReports_city on City {
      id
      name
      alias
    }
  `,
});

export default compose(
  inject18n,
  withStyles(styles),
)(CityReports);
