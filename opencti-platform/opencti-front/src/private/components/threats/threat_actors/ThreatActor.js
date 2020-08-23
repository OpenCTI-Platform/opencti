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
import EntityLastReports from '../../analysis/reports/EntityLastReports';
import EntityXOpenCTIIncidentsChart from '../../events/x_opencti_incidents/EntityXOpenCTIIncidentsChart';
import EntityReportsChart from '../../analysis/reports/EntityReportsChart';
import EntityCampaignsChart from '../campaigns/EntityCampaignsChart';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';
import StixCoreObjectNotes from '../../common/stix_core_objects/StixCoreObjectNotes';

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
        <StixDomainObjectHeader
          stixDomainObject={threatActor}
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
        <StixCoreObjectNotes entityId={threatActor.id} />
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
              relationshipType="attributed-to"
            />
          </Grid>
          <Grid item={true} xs={4}>
            <EntityXOpenCTIIncidentsChart
              entityId={threatActor.id}
              inferred={true}
            />
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
      aliases
      ...ThreatActorOverview_threatActor
      ...ThreatActorDetails_threatActor
    }
  `,
});

export default compose(inject18n, withStyles(styles))(ThreatActor);
