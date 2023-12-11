import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Switch, withRouter } from 'react-router-dom';
import { graphql, createFragmentContainer } from 'react-relay';
import EntityStixCoreRelationships from '../../common/stix_core_relationships/EntityStixCoreRelationships';
import StixDomainObjectKnowledge from '../../common/stix_domain_objects/StixDomainObjectKnowledge';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import StixDomainObjectAuthorKnowledge from '../../common/stix_domain_objects/StixDomainObjectAuthorKnowledge';
import StixSightingRelationship from '../../events/stix_sighting_relationships/StixSightingRelationship';

class IndividualKnowledgeComponent extends Component {
  render() {
    const { individual, viewAs } = this.props;
    const link = `/dashboard/entities/individuals/${individual.id}/knowledge`;
    return (
      <div style={{ paddingRight: viewAs === 'knowledge' ? 200 : 0 }}>
        <Switch>
          <Route
            exact
            path="/dashboard/entities/individuals/:individualId/knowledge/relations/:relationId"
            render={(routeProps) => (
              <StixCoreRelationship
                entityId={individual.id}
                paddingRight={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/individuals/:individualId/knowledge/sightings/:sightingId"
            render={(routeProps) => (
              <StixSightingRelationship
                entityId={individual.id}
                paddingRight={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/individuals/:individualId/knowledge/overview"
            render={(routeProps) => (viewAs === 'knowledge' ? (
              <StixDomainObjectKnowledge
                stixDomainObjectId={individual.id}
                stixDomainObjectType="Individual"
                {...routeProps}
              />
            ) : (
              <StixDomainObjectAuthorKnowledge
                stixDomainObjectId={individual.id}
                stixDomainObjectType="Individual"
                {...routeProps}
              />
            ))
            }
          />
          <Route
            exact
            path="/dashboard/entities/individuals/:individualId/knowledge/threats"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={individual.id}
                relationshipTypes={['targets']}
                isRelationReversed
                entityLink={link}
                stixCoreObjectTypes={[
                  'Attack-Pattern',
                  'Threat-Actor',
                  'Intrusion-Set',
                  'Campaign',
                  'Incident',
                  'Malware',
                  'Tool',
                ]}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/individuals/:individualId/knowledge/related"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={individual.id}
                relationshipTypes={['related-to']}
                entityLink={link}
                allDirections={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/individuals/:individualId/knowledge/organizations"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={individual.id}
                relationshipTypes={['part-of']}
                stixCoreObjectTypes={['Organization']}
                entityLink={link}
                isRelationReversed={false}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/individuals/:individualId/knowledge/locations"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={individual.id}
                relationshipTypes={['located-at']}
                stixCoreObjectTypes={['City', 'Country', 'Region']}
                entityLink={link}
                isRelationReversed={false}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/individuals/:individualId/knowledge/threat_actors"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={individual.id}
                relationshipTypes={['targets']}
                stixCoreObjectTypes={['Threat-Actor']}
                entityLink={link}
                isRelationReversed={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/individuals/:individualId/knowledge/intrusion_sets"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={individual.id}
                relationshipTypes={['targets']}
                stixCoreObjectTypes={['Intrusion-Set']}
                entityLink={link}
                isRelationReversed={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/individuals/:individualId/knowledge/campaigns"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={individual.id}
                relationshipTypes={['targets']}
                stixCoreObjectTypes={['Campaign']}
                entityLink={link}
                isRelationReversed={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/individuals/:individualId/knowledge/incidents"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={individual.id}
                relationshipTypes={['targets']}
                stixCoreObjectTypes={['Incident']}
                entityLink={link}
                isRelationReversed={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/individuals/:individualId/knowledge/malwares"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={individual.id}
                relationshipTypes={['targets']}
                stixCoreObjectTypes={['Malware']}
                entityLink={link}
                isRelationReversed={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/individuals/:individualId/knowledge/attack_patterns"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={individual.id}
                relationshipTypes={['targets']}
                stixCoreObjectTypes={['Attack-Pattern']}
                entityLink={link}
                isRelationReversed={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/individuals/:individualId/knowledge/tools"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={individual.id}
                relationshipTypes={['targets']}
                stixCoreObjectTypes={['Tool']}
                entityLink={link}
                isRelationReversed={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/individuals/:individualId/knowledge/observables"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={individual.id}
                relationshipTypes={['related-to']}
                stixCoreObjectTypes={['Stix-Cyber-Observable']}
                entityLink={link}
                allDirections={true}
                isRelationReversed={true}
                {...routeProps}
              />
            )}
          />
        </Switch>
      </div>
    );
  }
}

IndividualKnowledgeComponent.propTypes = {
  individual: PropTypes.object,
  viewAs: PropTypes.string,
};

const IndividualKnowledge = createFragmentContainer(
  IndividualKnowledgeComponent,
  {
    individual: graphql`
      fragment IndividualKnowledge_individual on Individual {
        id
        name
        x_opencti_aliases
      }
    `,
  },
);

export default withRouter(IndividualKnowledge);
