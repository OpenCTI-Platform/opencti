import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Grid from '@mui/material/Grid';
import inject18n from '../../../../components/i18n';
import ThreatActorGroupDetails from './ThreatActorGroupDetails';
import ThreatActorGroupEdition from './ThreatActorGroupEdition';
import ThreatActorGroupPopover from './ThreatActorGroupPopover';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import StixCoreObjectOrStixCoreRelationshipNotes from '../../analyses/notes/StixCoreObjectOrStixCoreRelationshipNotes';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import StixCoreObjectExternalReferences from '../../analyses/external_references/StixCoreObjectExternalReferences';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import SimpleStixObjectOrStixRelationshipStixCoreRelationships from '../../common/stix_core_relationships/SimpleStixObjectOrStixRelationshipStixCoreRelationships';
import StixCoreObjectOrStixRelationshipLastContainers from '../../common/containers/StixCoreObjectOrStixRelationshipLastContainers';

const styles = () => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
});

class ThreatActorGroupComponent extends Component {
  render() {
    const { classes, threatActorGroup } = this.props;
    return (
      <div className={classes.container}>
        <StixDomainObjectHeader
          entityType="Threat-Actor-Group"
          stixDomainObject={threatActorGroup}
          PopoverComponent={<ThreatActorGroupPopover />}
          enableQuickSubscription={true}
        />
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
        >
          <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
            <ThreatActorGroupDetails threatActorGroup={threatActorGroup} />
          </Grid>
          <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
            <StixDomainObjectOverview stixDomainObject={threatActorGroup} />
          </Grid>
          <Grid item={true} xs={6} style={{ marginTop: 30 }}>
            <SimpleStixObjectOrStixRelationshipStixCoreRelationships
              stixObjectOrStixRelationshipId={threatActorGroup.id}
              stixObjectOrStixRelationshipLink={`/dashboard/threats/threat_actors_group/${threatActorGroup.id}/knowledge`}
            />
          </Grid>
          <Grid item={true} xs={6} style={{ marginTop: 30 }}>
            <StixCoreObjectOrStixRelationshipLastContainers
              stixCoreObjectOrStixRelationshipId={threatActorGroup.id}
            />
          </Grid>
          <Grid item={true} xs={6} style={{ marginTop: 30 }}>
            <StixCoreObjectExternalReferences
              stixCoreObjectId={threatActorGroup.id}
            />
          </Grid>
          <Grid item={true} xs={6} style={{ marginTop: 30 }}>
            <StixCoreObjectLatestHistory
              stixCoreObjectId={threatActorGroup.id}
            />
          </Grid>
        </Grid>
        <StixCoreObjectOrStixCoreRelationshipNotes
          stixCoreObjectOrStixCoreRelationshipId={threatActorGroup.id}
          defaultMarkings={(threatActorGroup.objectMarking?.edges ?? []).map(
            (edge) => edge.node,
          )}
        />
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <ThreatActorGroupEdition threatActorGroupId={threatActorGroup.id} />
        </Security>
      </div>
    );
  }
}

ThreatActorGroupComponent.propTypes = {
  threatActorGroup: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const ThreatActorGroup = createFragmentContainer(ThreatActorGroupComponent, {
  threatActorGroup: graphql`
    fragment ThreatActorGroup_ThreatActorGroup on ThreatActorGroup {
      id
      standard_id
      entity_type
      x_opencti_stix_ids
      spec_version
      revoked
      confidence
      created
      modified
      created_at
      updated_at
      createdBy {
        ... on Identity {
          id
          name
          entity_type
          x_opencti_reliability
        }
      }
      creators {
        id
        name
      }
      objectMarking {
        edges {
          node {
            id
            definition
            definition_type
            definition
            x_opencti_order
            x_opencti_color
          }
        }
      }
      objectLabel {
        edges {
          node {
            id
            value
            color
          }
        }
      }
      name
      aliases
      status {
        id
        order
        template {
          name
          color
        }
      }
      workflowEnabled
      ...ThreatActorGroupDetails_ThreatActorGroup
    }
  `,
});

export default compose(inject18n, withStyles(styles))(ThreatActorGroup);
