import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import inject18n from '../../../../components/i18n';
import ThreatActorOverview from './ThreatActorOverview';
import ThreatActorDetails from './ThreatActorDetails';
import ThreatActorEdition from './ThreatActorEdition';
import ThreatActorPopover from './ThreatActorPopover';
import EntityLastReports from '../../reports/EntityLastReports';
import EntityIncidentsChart from '../incidents/EntityIncidentsChart';
import EntityReportsChart from '../../reports/EntityReportsChart';
import EntityCampaignsChart from '../campaigns/EntityCampaignsChart';
import StixDomainEntityHeader from '../../common/stix_domain_entities/StixDomainEntityHeader';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';
import StixObjectNotes from '../../common/stix_object/StixObjectNotes';

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
        <StixDomainEntityHeader
          stixDomainEntity={threatActor}
          PopoverComponent={<ThreatActorPopover />}
        />
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
        >
          <Grid item={true} xs={3}>
            <ThreatActorOverview threatActor={threatActor} />
          </Grid>
          <Grid item={true} xs={3}>
            <ThreatActorDetails threatActor={threatActor} />
          </Grid>
          <Grid item={true} xs={6}>
            <EntityLastReports entityId={threatActor.id} />
          </Grid>
        </Grid>
        <StixObjectNotes entityId={threatActor.id} />
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
          style={{ marginTop: 15 }}
        >
          <Grid item={true} xs={4}>
            <EntityCampaignsChart
              entityId={threatActor.id}
              inferred={true}
              relationType="attributed-to"
            />
          </Grid>
          <Grid item={true} xs={4}>
            <EntityIncidentsChart entityId={threatActor.id} inferred={true} />
          </Grid>
          <Grid item={true} xs={4}>
            <EntityReportsChart entityId={threatActor.id} />
          </Grid>
        </Grid>
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <ThreatActorEdition threatActorId={threatActor.id} />
        </Security>
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
      name
      alias
      ...ThreatActorOverview_threatActor
      ...ThreatActorDetails_threatActor
    }
  `,
});

export default compose(inject18n, withStyles(styles))(ThreatActor);
