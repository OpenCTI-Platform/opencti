import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import inject18n from '../../../components/i18n';
import ThreatActorHeader from './ThreatActorHeader';
import EntityReports from '../report/EntityReports';

const styles = () => ({
  container: {
    margin: 0,
  },
});

class ThreatActorReportsComponent extends Component {
  render() {
    const { classes, threatActor } = this.props;
    return (
      <div className={classes.container}>
        <ThreatActorHeader threatActor={threatActor}/>
        <div style={{ height: 20 }}/>
        <EntityReports entityId={threatActor.id}/>
      </div>
    );
  }
}

ThreatActorReportsComponent.propTypes = {
  threatActor: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const ThreatActorReports = createFragmentContainer(ThreatActorReportsComponent, {
  threatActor: graphql`
      fragment ThreatActorReports_threatActor on ThreatActor {
          id
          ...ThreatActorHeader_threatActor
      }
  `,
});

export default compose(
  inject18n,
  withStyles(styles),
)(ThreatActorReports);
