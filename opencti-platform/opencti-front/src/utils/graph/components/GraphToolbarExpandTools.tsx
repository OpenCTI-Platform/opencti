import { OpenWithOutlined, Undo } from '@mui/icons-material';
import React, { useState } from 'react';
import InvestigationExpandForm, { InvestigationExpandFormProps } from '@components/workspaces/investigations/InvestigationExpandForm';
import Dialog from '@mui/material/Dialog';
import setStackDataInSessionStorage from '@components/workspaces/investigations/utils/setStackDataInSessionStorage/setStackDataInSessionStorage';
import {
  getPreExpansionStateList,
  investigationPreExpansionStateListStorageKey,
  updatePreExpansionStateList,
} from '@components/workspaces/investigations/utils/investigationStorage';
import { graphql } from 'react-relay';
import InvestigationRollBackExpandDialog from '@components/workspaces/investigations/dialog/InvestigationRollBackExpandDialog';
import GraphToolbarItem from './GraphToolbarItem';
import { useFormatter } from '../../../components/i18n';
import { useGraphContext } from '../GraphContext';
import useGraphInteractions from '../utils/useGraphInteractions';
import { fetchQuery } from '../../../relay/environment';
import { GraphToolbarExpandToolsRelationshipsQuery$data } from './__generated__/GraphToolbarExpandToolsRelationshipsQuery.graphql';
import { ObjectToParse } from '../utils/useGraphParser';

const expandRelationshipsQuery = graphql`
  query GraphToolbarExpandToolsRelationshipsQuery($filters: FilterGroup) {
    stixRelationships(
      filters: $filters
    ) {
      edges {
        node {
          id
          entity_type
          parent_types
          is_inferred
          ... on StixRefRelationship {
            created_at
          }
          ... on StixCoreRelationship {
            start_time
            stop_time
            confidence
            relationship_type
            created
            created_at
            createdBy {
              ... on Identity {
                id
                name
                entity_type
              }
            }
            objectMarking {
              id
              definition_type
              definition
              x_opencti_order
              x_opencti_color
            }
          }
          ... on StixSightingRelationship {
            first_seen
            last_seen
            created_at
            createdBy {
              ... on Identity {
                id
                name
                entity_type
              }
            }
            objectMarking {
              id
              definition_type
              definition
              x_opencti_order
              x_opencti_color
            }
          }
          ... on StixRefRelationship {
            start_time
            stop_time
            relationship_type
            created_at
          }
          from {
            ... on BasicObject {
              id
              entity_type
              parent_types
            }
            ... on StixCoreObject {
              created_at
              updated_at
              numberOfConnectedElement
              createdBy {
                ... on Identity {
                  id
                  name
                  entity_type
                }
              }
              objectMarking {
                id
                definition_type
                definition
                x_opencti_order
                x_opencti_color
              }
            }
            ... on StixDomainObject {
              created
            }
            ... on AttackPattern {
              name
              x_mitre_id
            }
            ... on Campaign {
              name
              first_seen
              last_seen
            }
            ... on CourseOfAction {
              name
            }
            ... on Note {
              attribute_abstract
              content
            }
            ... on ObservedData {
              name
              first_observed
              last_observed
            }
            ... on Opinion {
              opinion
            }
            ... on Report {
              name
              published
            }
            ... on Grouping {
              name
              description
            }
            ... on Individual {
              name
            }
            ... on Organization {
              name
            }
            ... on Sector {
              name
            }
            ... on System {
              name
            }
            ... on Indicator {
              name
              valid_from
            }
            ... on Infrastructure {
              name
            }
            ... on IntrusionSet {
              name
              first_seen
              last_seen
            }
            ... on Position {
              name
              description
            }
            ... on City {
              name
              description
            }
            ... on AdministrativeArea {
              name
              description
            }
            ... on Country {
              name
              description
            }
            ... on Region {
              name
              description
            }
            ... on Malware {
              name
              first_seen
              last_seen
            }
            ... on MalwareAnalysis {
              result_name
            }
            ... on ThreatActor {
              name
              first_seen
              last_seen
            }
            ... on Tool {
              name
            }
            ... on Vulnerability {
              name
            }
            ... on Incident {
              name
              first_seen
              last_seen
            }
            ... on Event {
              name
              start_time
              stop_time
            }
            ... on Channel {
              name
            }
            ... on Narrative {
              name
            }
            ... on Language {
              name
            }
            ... on DataComponent {
              name
            }
            ... on DataSource {
              name
            }
            ... on Case {
              name
            }
            ... on Task {
              name
            }
            ... on StixCyberObservable {
              observable_value
            }
            ... on StixFile {
              observableName: name
              hashes {
                algorithm
                hash
              }
            }
            ... on StixMetaObject {
              created
            }
            ... on Label {
              value
              color
            }
            ... on KillChainPhase {
              kill_chain_name
              phase_name
            }
            ... on MarkingDefinition {
              definition
              x_opencti_color
            }
            ... on ExternalReference {
              url
              source_name
            }
            ... on BasicRelationship {
              id
              entity_type
              parent_types
            }
            ... on StixCoreRelationship {
              relationship_type
              start_time
              stop_time
              confidence
              created
              from {
                ... on BasicObject {
                  id
                  entity_type
                  parent_types
                }
                ... on BasicRelationship {
                  id
                  entity_type
                  parent_types
                }
                ... on StixCoreRelationship {
                  relationship_type
                }
              }
              to {
                ... on BasicObject {
                  id
                  entity_type
                  parent_types
                }
                ... on BasicRelationship {
                  id
                  entity_type
                  parent_types
                }
                ... on StixCoreRelationship {
                  relationship_type
                }
              }
              created_at
              createdBy {
                ... on Identity {
                  id
                  name
                  entity_type
                }
              }
              objectMarking {
                id
                definition_type
                definition
                x_opencti_order
                x_opencti_color
              }
            }
          }
          to {
            ... on BasicObject {
              id
              entity_type
              parent_types
            }
            ... on StixCoreObject {
              created_at
              updated_at
              numberOfConnectedElement
              createdBy {
                ... on Identity {
                  id
                  name
                  entity_type
                }
              }
              objectMarking {
                id
                definition_type
                definition
                x_opencti_order
                x_opencti_color
              }
            }
            ... on StixDomainObject {
              created
            }
            ... on AttackPattern {
              name
              x_mitre_id
            }
            ... on Campaign {
              name
              first_seen
              last_seen
            }
            ... on CourseOfAction {
              name
            }
            ... on Note {
              attribute_abstract
            }
            ... on ObservedData {
              name
              first_observed
              last_observed
            }
            ... on Opinion {
              opinion
            }
            ... on Report {
              name
              published
            }
            ... on Grouping {
              name
              description
            }
            ... on Individual {
              name
            }
            ... on Organization {
              name
            }
            ... on Sector {
              name
            }
            ... on System {
              name
            }
            ... on Indicator {
              name
              valid_from
            }
            ... on Infrastructure {
              name
            }
            ... on IntrusionSet {
              name
              first_seen
              last_seen
            }
            ... on Position {
              name
            }
            ... on City {
              name
            }
            ... on AdministrativeArea {
              name
            }
            ... on Country {
              name
            }
            ... on Region {
              name
            }
            ... on Malware {
              name
              first_seen
              last_seen
            }
            ... on MalwareAnalysis {
              result_name
            }
            ... on ThreatActor {
              name
              first_seen
              last_seen
            }
            ... on Tool {
              name
            }
            ... on Vulnerability {
              name
            }
            ... on Incident {
              name
              first_seen
              last_seen
            }
            ... on StixCyberObservable {
              observable_value
            }
            ... on StixFile {
              observableName: name
              hashes {
                algorithm
                hash
              }
            }
            ... on StixMetaObject {
              created
            }
            ... on Label {
              value
              color
            }
            ... on KillChainPhase {
              kill_chain_name
              phase_name
            }
            ... on MarkingDefinition {
              definition
              x_opencti_color
            }
            ... on ExternalReference {
              url
              source_name
            }
            ... on BasicRelationship {
              id
              entity_type
              parent_types
            }
            ... on StixCoreRelationship {
              relationship_type
              start_time
              stop_time
              confidence
              created
              from {
                ... on BasicObject {
                  id
                  entity_type
                  parent_types
                }
                ... on BasicRelationship {
                  id
                  entity_type
                  parent_types
                }
                ... on StixCoreRelationship {
                  relationship_type
                }
              }
              to {
                ... on BasicObject {
                  id
                  entity_type
                  parent_types
                }
                ... on BasicRelationship {
                  id
                  entity_type
                  parent_types
                }
                ... on StixCoreRelationship {
                  relationship_type
                }
              }
              created_at
              createdBy {
                ... on Identity {
                  id
                  name
                  entity_type
                }
              }
              objectMarking {
                id
                definition_type
                definition
                x_opencti_order
                x_opencti_color
              }
            }
          }
        }
      }
    }
  }
`;

const expandFilterGroup = (
  id: string,
  entityTypes: string[],
  relationshipTypes: string[],
) => ({
  mode: 'or',
  filterGroups: [
    {
      mode: 'and',
      filterGroups: [],
      filters: [
        { key: 'fromId', values: [id] },
        { key: 'toTypes', values: entityTypes },
        { key: 'relationship_type', values: relationshipTypes },
      ],
    },
    {
      mode: 'and',
      filterGroups: [],
      filters: [
        { key: 'toId', values: [id] },
        { key: 'fromTypes', values: entityTypes },
        { key: 'relationship_type', values: relationshipTypes },
      ],
    },
  ],
  filters: [],
});

export interface GraphToolbarExpandToolsProps {
  onInvestigationExpand?: (ids: string[]) => void
  onInvestigationRollback?: (ids: string[], onCompleted: () => void) => void
}

const GraphToolbarExpandTools = ({
  onInvestigationExpand,
  onInvestigationRollback,
}: GraphToolbarExpandToolsProps) => {
  const { t_i18n } = useFormatter();

  const {
    graphData,
    rawObjects,
    graphState: {
      selectedNodes,
      selectedLinks,
    },
  } = useGraphContext();

  const {
    setLinearProgress,
    addLink,
    addNode,
    rebuildGraphData,
  } = useGraphInteractions();

  const [expandOpen, setExpandOpen] = useState(false);
  const [rollBackOpen, setRollBackOpen] = useState(false);

  const onRollbackExpand = () => {
    const storedPreExpansion = getPreExpansionStateList();
    if (storedPreExpansion) {
      const currentStoredPreExpansion = JSON.parse(storedPreExpansion);
      const { investigatedEntitiesList } = currentStoredPreExpansion[0];
      const objectsToKeep = rawObjects.filter((o) => {
        return investigatedEntitiesList.find((e: { id: string }) => e.id === o.id);
      });
      const objectsToAdd = investigatedEntitiesList.filter((e: { id: string }) => {
        return !rawObjects.find((o) => e.id === o.id);
      });
      onInvestigationRollback?.(
        [...objectsToKeep, ...objectsToAdd].map((o) => o.id),
        () => {
          rebuildGraphData([...objectsToKeep, ...objectsToAdd]);
          updatePreExpansionStateList(currentStoredPreExpansion);
        },
      );
    }
  };

  const onExpand: InvestigationExpandFormProps['onSubmit'] = async (
    { entity_types, relationship_types },
    { resetForm },
  ) => {
    if (entity_types.length === 0 && relationship_types.length === 0) {
      // Do not expand if nothing has been checked.
      return;
    }

    setStackDataInSessionStorage(
      investigationPreExpansionStateListStorageKey,
      {
        dateTime: new Date().getTime(),
        investigatedEntitiesList: rawObjects,
      },
      10,
    );

    setLinearProgress(true);
    const entityTypes = entity_types.map((o) => o.value);
    const relationshipTypes = relationship_types.map((o) => o.value);
    const selectionIds = [...selectedNodes, ...selectedLinks].map((s) => s.id);
    const objectIds = rawObjects.map((o) => o.id);

    await Promise.all(selectionIds.map(async (id) => {
      const { stixRelationships } = (await fetchQuery(
        expandRelationshipsQuery,
        { filters: expandFilterGroup(id, entityTypes, relationshipTypes) },
      ).toPromise()) as GraphToolbarExpandToolsRelationshipsQuery$data;
      const newElements = (stixRelationships?.edges ?? []).flatMap((e) => {
        if (!e) return [];
        const entity = e.node.from?.id === id ? e.node.to : e.node.from;
        const toReturn: string[] = [];
        if (!objectIds.includes(e.node.id)) {
          toReturn.push(e.node.id);
          addLink(e.node as unknown as ObjectToParse);
        }
        if (!!entity?.id && !objectIds.includes(entity.id)) {
          toReturn.push(entity.id);
          addNode(entity as unknown as ObjectToParse);
        }
        return toReturn;
      });
      // this.fetchObjectRelCounts(newElements);
      onInvestigationExpand?.(newElements);
      return '';
    }));

    resetForm();
    setRollBackOpen(false);
    setLinearProgress(false);
  };

  return (
    <>
      <GraphToolbarItem
        Icon={<Undo />}
        color="primary"
        onClick={() => setRollBackOpen(true)}
        title={t_i18n('Restore the state of the graphic before the last expansion')}
        disabled={!getPreExpansionStateList()}
      />

      <InvestigationRollBackExpandDialog
        isOpen={rollBackOpen}
        closeDialog={() => setRollBackOpen(false)}
        handleRollBackToPreExpansionState={onRollbackExpand}
      />

      <GraphToolbarItem
        Icon={<OpenWithOutlined />}
        color="primary"
        onClick={() => setExpandOpen(true)}
        title={t_i18n('Expand')}
        disabled={selectedNodes.length === 0}
      />

      <Dialog
        fullWidth
        maxWidth="sm"
        open={expandOpen}
        PaperProps={{ elevation: 1 }}
        onClose={() => setExpandOpen(false)}
      >
        <InvestigationExpandForm
          links={graphData?.links ?? []}
          selectedNodes={selectedNodes}
          onSubmit={onExpand}
          onReset={() => setExpandOpen(false)}
        />
      </Dialog>
    </>
  );
};

export default GraphToolbarExpandTools;
