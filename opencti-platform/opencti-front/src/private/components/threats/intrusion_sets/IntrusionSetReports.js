import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import inject18n from '../../../../components/i18n';
import Reports from '../../reports/Reports';
import IntrusionSetPopover from './IntrusionSetPopover';
import StixDomainEntityHeader from '../../common/stix_domain_entities/StixDomainEntityHeader';

const styles = () => ({
  container: {
    margin: 0,
  },
  paper: {
    minHeight: '100%',
    margin: '5px 0 0 0',
    padding: '25px 15px 15px 15px',
    borderRadius: 6,
  },
});

class IntrusionSetReportsComponent extends Component {
  render() {
    const { classes, intrusionSet } = this.props;
    return (
      <div className={classes.container}>
        <StixDomainEntityHeader
          stixDomainEntity={intrusionSet}
          PopoverComponent={<IntrusionSetPopover />}
        />
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <Reports objectId={intrusionSet.id} />
        </Paper>
      </div>
    );
  }
}

IntrusionSetReportsComponent.propTypes = {
  intrusionSet: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const IntrusionSetReports = createFragmentContainer(
  IntrusionSetReportsComponent,
  {
    intrusionSet: graphql`
      fragment IntrusionSetReports_intrusionSet on IntrusionSet {
        id
        name
        alias
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles),
)(IntrusionSetReports);
