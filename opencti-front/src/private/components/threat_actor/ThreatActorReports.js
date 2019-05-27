import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import inject18n from '../../../components/i18n';
import ThreatActorHeader from './ThreatActorHeader';
import EntityReports from '../report/EntityReports';

const styles = theme => ({
  container: {
    margin: 0,
  },
  paper: {
    minHeight: '100%',
    margin: '5px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
});

class ThreatActorReportsComponent extends Component {
  render() {
    const { classes, threatActor } = this.props;
    return (
      <div className={classes.container}>
        <ThreatActorHeader threatActor={threatActor} />
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <EntityReports entityId={threatActor.id} />
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
        ...ThreatActorHeader_threatActor
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles),
)(ThreatActorReports);
