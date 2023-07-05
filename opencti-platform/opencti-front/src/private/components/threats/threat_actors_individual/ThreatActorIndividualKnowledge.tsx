/* eslint-disable @typescript-eslint/no-explicit-any */
// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React from 'react';
import { Route, Switch } from 'react-router-dom';
import { graphql, useFragment } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import EntityStixCoreRelationships from '../../common/stix_core_relationships/EntityStixCoreRelationships';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import StixDomainObjectAttackPatterns from '../../common/stix_domain_objects/StixDomainObjectAttackPatterns';
import StixDomainObjectThreatKnowledge from '../../common/stix_domain_objects/StixDomainObjectThreatKnowledge';
import StixDomainObjectVictimology from '../../common/stix_domain_objects/StixDomainObjectVictimology';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import StixSightingRelationship from '../../events/stix_sighting_relationships/StixSightingRelationship';
import ThreatActorIndividualPopover from './ThreatActorIndividualPopover';
import {
  ThreatActorIndividualKnowledge_ThreatActorIndividual$key,
} from './__generated__/ThreatActorIndividualKnowledge_ThreatActorIndividual.graphql';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
    padding: '0 200px 0 0',
  },
}));

const threatActorIndividualKnowledgeFragment = graphql`
fragment ThreatActorIndividualKnowledge_ThreatActorIndividual on ThreatActorIndividual {
  id
  name
  aliases
  first_seen
  last_seen
  }
`;

const ThreatActorIndividualKnowledgeComponent = ({
  threatActorIndividualData,
}: {
  threatActorIndividualData: ThreatActorIndividualKnowledge_ThreatActorIndividual$key
}) => {
  const classes = useStyles();
  const threatActorIndividual = useFragment<ThreatActorIndividualKnowledge_ThreatActorIndividual$key>(
    threatActorIndividualKnowledgeFragment,
    threatActorIndividualData,
  );
  const link = `/dashboard/threats/threat_actors_individual/${threatActorIndividual.id}/knowledge`;
  return (
    <div className={classes.container}>
      <StixDomainObjectHeader
        entityType={'Threat-Actor-Individual'}
        stixDomainObject={threatActorIndividual}
        PopoverComponent={<ThreatActorIndividualPopover id={threatActorIndividual.id} />}
      />
      <Switch>
        <Route
        exact
        path="/dashboard/threats/threat_actors_individual/:threatActorIndividualId/knowledge/relations/:relationId"
        render={(routeProps: any) => (
          <StixCoreRelationship
            entityId={threatActorIndividual.id}
            paddingRight={true}
            {...routeProps}
          />
        )}
      />
      <Route
        exact
        path="/dashboard/threats/threat_actors_individual/:threatActorIndividualId/knowledge/sightings/:sightingId"
        render={(routeProps: any) => (
          <StixSightingRelationship
            entityId={threatActorIndividual.id}
            paddingRight={true}
            {...routeProps}
          />
        )}
      />
      <Route
        exact
        path="/dashboard/threats/threat_actors_individual/:threatActorIndividualId/knowledge/overview"
        render={(routeProps: any) => (
          <StixDomainObjectThreatKnowledge
            stixDomainObjectId={threatActorIndividual.id}
            stixDomainObjectType="Threat-Actor-Individual"
            {...routeProps}
          />
        )}
      />
      <Route
        exact
        path="/dashboard/threats/threat_actors_individual/:threatActorIndividualId/knowledge/related"
        render={(routeProps: any) => (
          <EntityStixCoreRelationships
            entityId={threatActorIndividual.id}
            relationshipTypes={['related-to', 'part-of']}
            entityLink={link}
            defaultStartTime={threatActorIndividual.first_seen}
            defaultStopTime={threatActorIndividual.last_seen}
            allDirections={true}
            {...routeProps}
          />
        )}
      />
      <Route
        exact
        path="/dashboard/threats/threat_actors_individual/:threatActorIndividualId/knowledge/victimology"
        render={(routeProps: any) => (
          <StixDomainObjectVictimology
            stixDomainObjectId={threatActorIndividual.id}
            entityLink={link}
            defaultStartTime={threatActorIndividual.first_seen}
            defaultStopTime={threatActorIndividual.last_seen}
            {...routeProps}
          />
        )}
      />
      <Route
        exact
        path="/dashboard/threats/threat_actors_individual/:threatActorIndividualId/knowledge/threat_actors_individual"
        render={(routeProps: any) => (
          <EntityStixCoreRelationships
            entityId={threatActorIndividual.id}
            relationshipTypes={['part-of', 'cooperates-with']}
            stixCoreObjectTypes={['Threat-Actor-Individual']}
            entityLink={link}
            defaultStartTime={threatActorIndividual.first_seen}
            defaultStopTime={threatActorIndividual.last_seen}
            allDirections={true}
            {...routeProps}
          />
        )}
      />
      <Route
        exact
        path="/dashboard/threats/threat_actors_individual/:threatActorIndividualId/knowledge/intrusion_sets"
        render={(routeProps: any) => (
          <EntityStixCoreRelationships
            entityId={threatActorIndividual.id}
            relationshipTypes={['attributed-to']}
            stixCoreObjectTypes={['Intrusion-Set']}
            entityLink={link}
            defaultStartTime={threatActorIndividual.first_seen}
            defaultStopTime={threatActorIndividual.last_seen}
            isRelationReversed={true}
            {...routeProps}
          />
        )}
      />
      <Route
        exact
        path="/dashboard/threats/threat_actors_individual/:threatActorIndividualId/knowledge/campaigns"
        render={(routeProps: any) => (
          <EntityStixCoreRelationships
            entityId={threatActorIndividual.id}
            relationshipTypes={['attributed-to', 'participates-in']}
            stixCoreObjectTypes={['Campaign']}
            entityLink={link}
            defaultStartTime={threatActorIndividual.first_seen}
            defaultStopTime={threatActorIndividual.last_seen}
            allDirections={true}
            {...routeProps}
          />
        )}
      />
      <Route
        exact
        path="/dashboard/threats/threat_actors_individual/:threatActorIndividualId/knowledge/attack_patterns"
        render={(routeProps: any) => (
          <StixDomainObjectAttackPatterns
            stixDomainObjectId={threatActorIndividual.id}
            entityLink={link}
            defaultStartTime={threatActorIndividual.first_seen}
            defaultStopTime={threatActorIndividual.last_seen}
            {...routeProps}
          />
        )}
      />
      <Route
        exact
        path="/dashboard/threats/threat_actors_individual/:threatActorIndividualId/knowledge/malwares"
        render={(routeProps: any) => (
          <EntityStixCoreRelationships
            entityId={threatActorIndividual.id}
            relationshipTypes={['uses']}
            stixCoreObjectTypes={['Malware']}
            entityLink={link}
            defaultStartTime={threatActorIndividual.first_seen}
            defaultStopTime={threatActorIndividual.last_seen}
            {...routeProps}
          />
        )}
      />
      <Route
        exact
        path="/dashboard/threats/threat_actors_individual/:threatActorIndividualId/knowledge/channels"
        render={(routeProps: any) => (
          <EntityStixCoreRelationships
            entityId={threatActorIndividual.id}
            relationshipTypes={['uses']}
            stixCoreObjectTypes={['Channel']}
            entityLink={link}
            defaultStartTime={threatActorIndividual.first_seen}
            defaultStopTime={threatActorIndividual.last_seen}
            {...routeProps}
          />
        )}
      />
      <Route
        exact
        path="/dashboard/threats/threat_actors_individual/:threatActorIndividualId/knowledge/narratives"
        render={(routeProps: any) => (
          <EntityStixCoreRelationships
            entityId={threatActorIndividual.id}
            relationshipTypes={['uses']}
            stixCoreObjectTypes={['Narrative']}
            entityLink={link}
            defaultStartTime={threatActorIndividual.first_seen}
            defaultStopTime={threatActorIndividual.last_seen}
            {...routeProps}
          />
        )}
      />
      <Route
        exact
        path="/dashboard/threats/threat_actors_individual/:threatActorIndividualId/knowledge/tools"
        render={(routeProps: any) => (
          <EntityStixCoreRelationships
            entityId={threatActorIndividual.id}
            relationshipTypes={['uses']}
            stixCoreObjectTypes={['Tool']}
            entityLink={link}
            defaultStartTime={threatActorIndividual.first_seen}
            defaultStopTime={threatActorIndividual.last_seen}
            {...routeProps}
          />
        )}
      />
      <Route
        exact
        path="/dashboard/threats/threat_actors_individual/:threatActorIndividualId/knowledge/vulnerabilities"
        render={(routeProps: any) => (
          <EntityStixCoreRelationships
            entityId={threatActorIndividual.id}
            relationshipTypes={['targets']}
            stixCoreObjectTypes={['Vulnerability']}
            entityLink={link}
            defaultStartTime={threatActorIndividual.first_seen}
            defaultStopTime={threatActorIndividual.last_seen}
            {...routeProps}
          />
        )}
      />
      <Route
        exact
        path="/dashboard/threats/threat_actors_individual/:threatActorIndividualId/knowledge/incidents"
        render={(routeProps: any) => (
          <EntityStixCoreRelationships
            entityId={threatActorIndividual.id}
            relationshipTypes={['attributed-to']}
            stixCoreObjectTypes={['Incident']}
            entityLink={link}
            isRelationReversed={true}
            defaultStartTime={threatActorIndividual.first_seen}
            defaultStopTime={threatActorIndividual.last_seen}
            {...routeProps}
          />
        )}
      />
      <Route
        exact
        path="/dashboard/threats/threat_actors_individual/:threatActorIndividualId/knowledge/observables"
        render={(routeProps: any) => (
          <EntityStixCoreRelationships
            entityId={threatActorIndividual.id}
            relationshipTypes={['related-to']}
            stixCoreObjectTypes={['Stix-Cyber-Observable']}
            entityLink={link}
            defaultStartTime={threatActorIndividual.first_seen}
            defaultStopTime={threatActorIndividual.last_seen}
            allDirections={true}
            isRelationReversed={true}
            {...routeProps}
          />
        )}
      />
      <Route
        exact
        path="/dashboard/threats/threat_actors_individual/:threatActorIndividualId/knowledge/infrastructures"
        render={(routeProps: any) => (
          <EntityStixCoreRelationships
            entityId={threatActorIndividual.id}
            relationshipTypes={['uses', 'compromises']}
            stixCoreObjectTypes={['Infrastructure']}
            entityLink={link}
            isRelationReversed={false}
            defaultStartTime={threatActorIndividual.first_seen}
            defaultStopTime={threatActorIndividual.last_seen}
            {...routeProps}
          />
        )}
      />
      <Route
        exact
        path="/dashboard/threats/threat_actors_individual/:threatActorIndividualId/knowledge/sightings"
        render={(routeProps: any) => (
          <EntityStixSightingRelationships
            entityId={threatActorIndividual.id}
            entityLink={link}
            noRightBar={true}
            defaultStartTime={threatActorIndividual.first_seen}
            defaultStopTime={threatActorIndividual.last_seen}
            stixCoreObjectTypes={[
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
};

export default ThreatActorIndividualKnowledgeComponent;
