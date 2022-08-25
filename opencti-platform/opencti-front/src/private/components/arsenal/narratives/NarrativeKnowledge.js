import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Switch, withRouter } from 'react-router-dom';
import { compose } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import inject18n from '../../../../components/i18n';
import EntityStixCoreRelationships from '../../common/stix_core_relationships/EntityStixCoreRelationships';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import NarrativePopover from './NarrativePopover';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import StixCoreObjectStixCyberObservables from '../../observations/stix_cyber_observables/StixCoreObjectStixCyberObservables';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import StixDomainObjectThreatKnowledge from '../../common/stix_domain_objects/StixDomainObjectThreatKnowledge';
import StixSightingRelationship from '../../events/stix_sighting_relationships/StixSightingRelationship';

const styles = () => ({
  container: {
    margin: 0,
    padding: '0 200px 0 0',
  },
});

class NarrativeKnowledgeComponent extends Component {
  render() {
    const { classes, narrative } = this.props;
    const link = `/dashboard/arsenal/narratives/${narrative.id}/knowledge`;
    return (
      <div className={classes.container}>
        <StixDomainObjectHeader
          stixDomainObject={narrative}
          PopoverComponent={<NarrativePopover />}
        />
        <Switch>
          <Route
            exact
            path="/dashboard/arsenal/narratives/:narrativeId/knowledge/relations/:relationId"
            render={(routeProps) => (
              <StixCoreRelationship
                entityId={narrative.id}
                paddingRight={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/arsenal/narratives/:narrativeId/knowledge/sightings/:sightingId"
            render={(routeProps) => (
              <StixSightingRelationship
                entityId={narrative.id}
                paddingRight={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/arsenal/narratives/:narrativeId/knowledge/overview"
            render={(routeProps) => (
              <StixDomainObjectThreatKnowledge
                stixDomainObjectId={narrative.id}
                stixDomainObjectType="Narrative"
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/arsenal/narratives/:narrativeId/knowledge/related"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={narrative.id}
                relationshipTypes={['related-to']}
                targetStixDomainObjectTypes={[
                  'Threat-Actor',
                  'Intrusion-Set',
                  'Campaign',
                  'Incident',
                  'Malware',
                  'Narrative',
                  'Vulnerability',
                  'Individual',
                  'Organization',
                  'Sector',
                  'Region',
                  'Country',
                  'City',
                  'Position',
                ]}
                entityLink={link}
                allDirections={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/arsenal/narratives/:narrativeId/knowledge/threat_actors"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={narrative.id}
                relationshipTypes={['uses']}
                targetStixDomainObjectTypes={['Threat-Actor']}
                entityLink={link}
                isRelationReversed={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/arsenal/narratives/:narrativeId/knowledge/intrusion_sets"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={narrative.id}
                relationshipTypes={['uses']}
                targetStixDomainObjectTypes={['Intrusion-Set']}
                entityLink={link}
                isRelationReversed={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/arsenal/narratives/:narrativeId/knowledge/campaigns"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={narrative.id}
                relationshipTypes={['uses']}
                targetStixDomainObjectTypes={['Campaign']}
                entityLink={link}
                isRelationReversed={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/arsenal/narratives/:narrativeId/knowledge/attack_patterns"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={narrative.id}
                relationshipTypes={['uses']}
                targetStixDomainObjectTypes={['Attack-Pattern']}
                entityLink={link}
                isRelationReversed={false}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/arsenal/narratives/:narrativeId/knowledge/malwares"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={narrative.id}
                relationshipTypes={['uses']}
                targetStixDomainObjectTypes={['Malware']}
                entityLink={link}
                isRelationReversed={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/arsenal/narratives/:narrativeId/knowledge/channels"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={narrative.id}
                relationshipTypes={['uses']}
                targetStixDomainObjectTypes={['Channel']}
                entityLink={link}
                isRelationReversed={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/arsenal/narratives/:narrativeId/knowledge/vulnerabilities"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={narrative.id}
                relationshipTypes={['uses']}
                targetStixDomainObjectTypes={['Vulnerability']}
                entityLink={link}
                isRelationReversed={false}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/arsenal/narratives/:narrativeId/knowledge/incidents"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={narrative.id}
                relationshipTypes={['uses']}
                targetStixDomainObjectTypes={['Incident']}
                entityLink={link}
                isRelationReversed={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/arsenal/narratives/:narrativeId/knowledge/observables"
            render={(routeProps) => (
              <StixCoreObjectStixCyberObservables
                stixCoreObjectId={narrative.id}
                stixCoreObjectLink={link}
                noRightBar={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/arsenal/narratives/:narrativeId/knowledge/sightings"
            render={(routeProps) => (
              <EntityStixSightingRelationships
                entityId={narrative.id}
                entityLink={link}
                noRightBar={true}
                targetStixDomainObjectTypes={[
                  'Region',
                  'Country',
                  'City',
                  'Position',
                  'Sector',
                  'Organization',
                  'Individual',
                  'System',
                ]}
                {...routeProps}
              />
            )}
          />
        </Switch>
      </div>
    );
  }
}

NarrativeKnowledgeComponent.propTypes = {
  narrative: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const NarrativeKnowledge = createFragmentContainer(
  NarrativeKnowledgeComponent,
  {
    narrative: graphql`
      fragment NarrativeKnowledge_narrative on Narrative {
        id
        name
        aliases
      }
    `,
  },
);

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(NarrativeKnowledge);
