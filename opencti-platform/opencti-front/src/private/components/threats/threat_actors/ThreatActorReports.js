import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import inject18n from '../../../../components/i18n';
import ThreatActorPopover from './ThreatActorPopover';
import Reports from '../../reports/Reports';
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

class ThreatActorReportsComponent extends Component {
  render() {
    const { classes, threatActor } = this.props;
    return (
      <div className={classes.container}>
        <StixDomainEntityHeader
          stixDomainEntity={threatActor}
          PopoverComponent={<ThreatActorPopover />}
        />
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <Reports objectId={threatActor.id} />
        </Paper>
      </div>
    );
  }
}

ThreatActorReportsComponent.propTypes = {
  threatActor: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const ThreatActorReports = createFragmentContainer(
  ThreatActorReportsComponent,
  {
    threatActor: graphql`
      fragment ThreatActorReports_threatActor on ThreatActor {
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
)(ThreatActorReports);
