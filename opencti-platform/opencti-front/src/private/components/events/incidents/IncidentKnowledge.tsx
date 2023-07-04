/* eslint-disable @typescript-eslint/no-explicit-any */
// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React from 'react';
import { Route, Switch } from 'react-router-dom';
import { graphql, useFragment } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import EntityStixCoreRelationships from '../../common/stix_core_relationships/EntityStixCoreRelationships';
import StixDomainObjectThreatKnowledge from '../../common/stix_domain_objects/StixDomainObjectThreatKnowledge';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import IncidentPopover from './IncidentPopover';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import StixDomainObjectAttackPatterns from '../../common/stix_domain_objects/StixDomainObjectAttackPatterns';
import StixDomainObjectVictimology from '../../common/stix_domain_objects/StixDomainObjectVictimology';
import StixSightingRelationship from '../stix_sighting_relationships/StixSightingRelationship';
import { IncidentKnowledge_incident$key } from './__generated__/IncidentKnowledge_incident.graphql';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
    padding: '0 200px 0 0',
  },
}));

const IncidentKnowledgeFragment = graphql`
  fragment IncidentKnowledge_incident on Incident {
    id
    name
    aliases
    first_seen
    last_seen
  }
`;

const IncidentKnowledge = ({
  incidentData,
}: {
  incidentData: IncidentKnowledge_incident$key;
}) => {
  const classes = useStyles();

  const incident = useFragment<IncidentKnowledge_incident$key>(
    IncidentKnowledgeFragment,
    incidentData,
  );
  const link = `/dashboard/events/incidents/${incident.id}/knowledge`;

  return (
    <div className={classes.container}>
      <StixDomainObjectHeader
        entityType={'Incident'}
        stixDomainObject={incident}
        PopoverComponent={IncidentPopover}
      />
      <Switch>
        <Route
          exact
          path="/dashboard/events/incidents/:incidentId/knowledge/relations/:relationId"
          render={(routeProps) => (
            <StixCoreRelationship
              entityId={incident.id}
              paddingRight={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/events/incidents/:incidentId/knowledge/sightings/:sightingId"
          render={(routeProps) => (
            <StixSightingRelationship
              entityId={incident.id}
              paddingRight={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/events/incidents/:incidentId/knowledge/overview"
          render={(routeProps) => (
            <StixDomainObjectThreatKnowledge
              stixDomainObjectId={incident.id}
              stixDomainObjectType="Incident"
              displayObservablesStats={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/events/incidents/:incidentId/knowledge/related"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={incident.id}
              relationshipTypes={['related-to']}
              entityLink={link}
              defaultStartTime={incident.first_seen}
              defaultStopTime={incident.last_seen}
              allDirections={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/events/incidents/:incidentId/knowledge/attribution"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={incident.id}
              relationshipTypes={['attributed-to']}
              stixCoreObjectTypes={[
                'Theat-Actor-Group',
                'Intrusion-Set',
                'Campaign',
              ]}
              entityLink={link}
              defaultStartTime={incident.first_seen}
              defaultStopTime={incident.last_seen}
              isRelationReversed={false}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/events/incidents/:incidentId/knowledge/victimology"
          render={(routeProps) => (
            <StixDomainObjectVictimology
              stixDomainObjectId={incident.id}
              entityLink={link}
              defaultStartTime={incident.first_seen}
              defaultStopTime={incident.last_seen}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/events/incidents/:incidentId/knowledge/attack_patterns"
          render={(routeProps) => (
            <StixDomainObjectAttackPatterns
              stixDomainObjectId={incident.id}
              entityLink={link}
              defaultStartTime={incident.first_seen}
              defaultStopTime={incident.last_seen}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/events/incidents/:incidentId/knowledge/malwares"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={incident.id}
              relationshipTypes={['uses']}
              stixCoreObjectTypes={['Malware']}
              entityLink={link}
              defaultStartTime={incident.first_seen}
              defaultStopTime={incident.last_seen}
              isRelationReversed={false}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/events/incidents/:incidentId/knowledge/narratives"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={incident.id}
              relationshipTypes={['uses']}
              stixCoreObjectTypes={['Narrative']}
              entityLink={link}
              defaultStartTime={incident.first_seen}
              defaultStopTime={incident.last_seen}
              isRelationReversed={false}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/events/incidents/:incidentId/knowledge/channels"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={incident.id}
              relationshipTypes={['uses']}
              stixCoreObjectTypes={['Channel']}
              entityLink={link}
              defaultStartTime={incident.first_seen}
              defaultStopTime={incident.last_seen}
              isRelationReversed={false}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/events/incidents/:incidentId/knowledge/tools"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={incident.id}
              relationshipTypes={['uses']}
              stixCoreObjectTypes={['Tool']}
              entityLink={link}
              defaultStartTime={incident.first_seen}
              defaultStopTime={incident.last_seen}
              isRelationReversed={false}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/events/incidents/:incidentId/knowledge/vulnerabilities"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={incident.id}
              relationshipTypes={['targets']}
              stixCoreObjectTypes={['Vulnerability']}
              entityLink={link}
              defaultStartTime={incident.first_seen}
              defaultStopTime={incident.last_seen}
              isRelationReversed={false}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/events/incidents/:incidentId/knowledge/observables"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={incident.id}
              relationshipTypes={['related-to']}
              stixCoreObjectTypes={['Stix-Cyber-Observable']}
              entityLink={link}
              defaultStartTime={incident.first_seen}
              defaultStopTime={incident.last_seen}
              allDirections={true}
              isRelationReversed={true}
              {...routeProps}
            />
          )}
        />
      </Switch>
    </div>
  );
};

export default IncidentKnowledge;
