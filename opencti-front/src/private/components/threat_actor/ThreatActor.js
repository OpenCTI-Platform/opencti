import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import inject18n from '../../../components/i18n';
import ThreatActorHeader from './ThreatActorHeader';
import ThreatActorOverview from './ThreatActorOverview';
import ThreatActorIdentity from './ThreatActorIdentity';
import ThreatActorEdition from './ThreatActorEdition';
import EntityLastReports from '../report/EntityLastReports';
import EntityObservablesChart from '../observable/EntityObservablesChart';
import EntityReportsChart from '../report/EntityReportsChart';
import EntityCampaignsChart from '../campaign/EntityCampaignsChart';

const styles = () => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
});

class ThreatActorComponent extends Component {
  render() {
    const { classes, threatActor } = this.props;
    return (
      <div className={classes.container}>
        <ThreatActorHeader threatActor={threatActor}/>
        <Grid container={true} spacing={32} classes={{ container: classes.gridContainer }}>
          <Grid item={true} xs={3}>
            <ThreatActorOverview threatActor={threatActor}/>
          </Grid>
          <Grid item={true} xs={3}>
            <ThreatActorIdentity threatActor={threatActor}/>
          </Grid>
          <Grid item={true} xs={6}>
            <EntityLastReports entityId={threatActor.id}/>
          </Grid>
        </Grid>
        <Grid container={true} spacing={32} classes={{ container: classes.gridContainer }} style={{ marginTop: 20 }}>
          <Grid item={true} xs={4}>
            <EntityObservablesChart entityId={threatActor.id}/>
          </Grid>
          <Grid item={true} xs={4}>
            <EntityCampaignsChart entityId={threatActor.id}/>
          </Grid>
          <Grid item={true} xs={4}>
            <EntityReportsChart entityId={threatActor.id}/>
          </Grid>
        </Grid>
        <ThreatActorEdition threatActorId={threatActor.id}/>
      </div>
    );
  }
}

ThreatActorComponent.propTypes = {
  threatActor: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const ThreatActor = createFragmentContainer(ThreatActorComponent, {
  threatActor: graphql`
      fragment ThreatActor_threatActor on ThreatActor {
          id
          ...ThreatActorHeader_threatActor
          ...ThreatActorOverview_threatActor
          ...ThreatActorIdentity_threatActor
      }
  `,
});

export default compose(
  inject18n,
  withStyles(styles),
)(ThreatActor);
