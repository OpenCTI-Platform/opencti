import React, { useState } from 'react';
import { createFragmentContainer, graphql, useLazyLoadQuery } from 'react-relay';
import Typography from '@mui/material/Typography';
import { Link } from 'react-router-dom';
import Tooltip from '@mui/material/Tooltip';
import { ChartTimeline, VectorLink, VectorPolygon } from 'mdi-material-ui';
import { AddTaskOutlined, AssistantOutlined, DifferenceOutlined, ViewColumnOutlined } from '@mui/icons-material';
import ToggleButton from '@mui/material/ToggleButton';
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup';
import { DialogTitle } from '@mui/material';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import Badge from '@mui/material/Badge';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import IconButton from '@mui/material/IconButton';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Select from '@mui/material/Select';
import MenuItem from '@mui/material/MenuItem';
import CircularProgress from '@mui/material/CircularProgress';
import { makeStyles } from '@mui/styles';
import Box from '@mui/material/Box';
import { stixCoreObjectQuickSubscriptionContentQuery } from '../stix_core_objects/stixCoreObjectTriggersUtils';
import StixCoreObjectAskAI from '../stix_core_objects/StixCoreObjectAskAI';
import { useSettingsMessagesBannerHeight } from '../../settings/settings_messages/SettingsMessagesBanner';
import StixCoreObjectSubscribers from '../stix_core_objects/StixCoreObjectSubscribers';
import FormAuthorizedMembersDialog from '../form/FormAuthorizedMembersDialog';
import ExportButtons from '../../../../components/ExportButtons';
import Security from '../../../../utils/Security';
import { useFormatter } from '../../../../components/i18n';
import { truncate } from '../../../../utils/String';
import { commitMutation, MESSAGING$, QueryRenderer } from '../../../../relay/environment';
import { getMainRepresentative } from '../../../../utils/defaultRepresentatives';
import { stixCoreRelationshipCreationMutation } from '../stix_core_relationships/StixCoreRelationshipCreation';
import { containerAddStixCoreObjectsLinesRelationAddMutation } from './ContainerAddStixCoreObjectsLines';
import StixCoreObjectSharing from '../stix_core_objects/StixCoreObjectSharing';
import useGranted, { KNOWLEDGE_KNENRICHMENT, KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS } from '../../../../utils/hooks/useGranted';
import StixCoreObjectQuickSubscription from '../stix_core_objects/StixCoreObjectQuickSubscription';
import MarkdownDisplay from '../../../../components/MarkdownDisplay';
import StixCoreObjectFileExport from '../stix_core_objects/StixCoreObjectFileExport';
import Transition from '../../../../components/Transition';
import { authorizedMembersToOptions } from '../../../../utils/authorizedMembers';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useHelper from '../../../../utils/hooks/useHelper';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles({
  containerDefault: {
    marginTop: 0,
  },
  title: {
    float: 'left',
  },
  popover: {
    float: 'left',
    marginTop: '-13px',
  },
  modes: {
    margin: '-6px 20px 0 20px',
    float: 'right',
  },
  actions: {
    margin: '-6px 0 0 0',
    float: 'right',
  },
  actionButtons: {
    display: 'flex',
  },
  export: {
    margin: '-6px 0 0 0',
    float: 'right',
  },
});

export const containerHeaderObjectsQuery = graphql`
  query ContainerHeaderObjectsQuery($id: String!) {
    container(id: $id) {
      id
      x_opencti_graph_data
      confidence
      createdBy {
        ... on Identity {
          id
          name
          entity_type
        }
      }
      creators {
        id
      }
      objectMarking {
        id
        definition_type
        definition
        x_opencti_order
        x_opencti_color
      }
      objects(all: true) {
        edges {
          types
          node {
            ... on BasicObject {
              id
              entity_type
              parent_types
            }
            ... on StixCoreObject {
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
            ... on StixDomainObject {
              is_inferred
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
            ... on ObservedData {
              name
            }
            ... on CourseOfAction {
              name
            }
            ... on Note {
              attribute_abstract
              content
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
              description
              start_time
              stop_time
            }
            ... on Channel {
              name
              description
            }
            ... on Narrative {
              name
              description
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
            ... on Feedback {
              name
            }
            ... on CaseIncident {
              name
            }
            ... on StixCyberObservable {
              observable_value
            }
            ... on StixFile {
              observableName: name
            }
            ... on Label {
              value
              color
            }
            ... on MarkingDefinition {
              definition
              x_opencti_color
            }
            ... on KillChainPhase {
              kill_chain_name
              phase_name
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
              is_inferred
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
            ... on StixRefRelationship {
              relationship_type
              start_time
              stop_time
              confidence
              is_inferred
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
              objectMarking {
                id
                definition_type
                definition
                x_opencti_order
                x_opencti_color
              }
            }
            ... on StixSightingRelationship {
              relationship_type
              first_seen
              last_seen
              confidence
              created
              is_inferred
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

const ContainerHeader = (props) => {
  const {
    container,
    PopoverComponent,
    popoverSecurity,
    link,
    modes,
    currentMode,
    knowledge,
    disableSharing,
    adjust,
    enableSuggestions,
    onApplied,
    enableQuickSubscription,
    investigationAddFromContainer,
    enableManageAuthorizedMembers,
    authorizedMembersMutation,
    enableAskAi,
    redirectToContent,
  } = props;
  const classes = useStyles();
  const { t_i18n, fd } = useFormatter();
  const userIsKnowledgeEditor = useGranted([KNOWLEDGE_KNUPDATE]);
  const [displaySuggestions, setDisplaySuggestions] = useState(false);
  const [selectedEntity, setSelectedEntity] = useState({});
  const [applying, setApplying] = useState([]);
  const [applied, setApplied] = useState([]);
  const { isFeatureEnable } = useHelper();
  const contentMappingFeatureFlag = isFeatureEnable('CONTENT_MAPPING');
  // Suggestions
  const resolveThreats = (objects) => objects.filter(
    (o) => [
      'Threat-Actor',
      'Intrusion-Set',
      'Campaign',
      'Incident',
      'Malware',
      'Tool',
    ].includes(o.entity_type) && o.types.includes('manual'),
  );
  const resolveIndicators = (objects) => objects.filter(
    (o) => ['Indicator'].includes(o.entity_type) && o.types.includes('manual'),
  );
  const resolveArsenal = (objects) => objects.filter(
    (o) => ['Attack-Pattern', 'Malware', 'Tool', 'Channel', 'Narrative'].includes(
      o.entity_type,
    ) && o.types.includes('manual'),
  );
  const resolveTargets = (objects) => objects.filter(
    (o) => [
      'Sector',
      'Region',
      'Country',
      'City',
      'Position',
      'Organization',
      'System',
      'Individual',
      'Vulnerability',
    ].includes(o.entity_type) && o.types.includes('manual'),
  );
  const setAppliedSuggestion = (suggestion) => {
    const appliedSuggestions = JSON.parse(
      localStorage.getItem(`suggestions-rules-${container.id}`) || '[]',
    );
    localStorage.setItem(
      `suggestions-rules-${container.id}`,
      JSON.stringify([...appliedSuggestions, suggestion]),
    );
  };
  const getAppliedSuggestions = () => {
    return JSON.parse(
      localStorage.getItem(`suggestions-rules-${container.id}`) || '[]',
    );
  };

  const generateSuggestions = (objects) => {
    const suggestions = [];
    const resolvedThreats = resolveThreats(objects);
    const resolvedIndicators = resolveIndicators(objects);
    const resolvedArsenal = resolveArsenal(objects);
    const resolvedTargets = resolveTargets(objects);
    // Threats and indicators
    if (resolvedThreats.length > 0 && resolvedIndicators.length > 0) {
      suggestions.push({ type: 'threats-indicators', data: resolvedThreats });
    }
    // Threats and arsenal
    if (resolvedThreats.length > 0 && resolvedArsenal.length > 0) {
      suggestions.push({ type: 'threats-arsenal', data: resolvedThreats });
    }
    // Threats and targets
    if (resolvedThreats.length > 0 && resolvedTargets.length > 0) {
      suggestions.push({ type: 'threats-targets', data: resolvedThreats });
    }
    return suggestions;
  };
  const handleSelectEntity = (type, event) => {
    if (event && event.target && event.target.value) {
      setSelectedEntity({ ...selectedEntity, [type]: event.target.value });
    }
  };
  // eslint-disable-next-line consistent-return
  const applySuggestion = async (type, objects) => {
    if (type === 'threats-indicators' && selectedEntity) {
      // create all indicates relationships
      setApplying([...applying, type]);
      const resolvedIndicators = resolveIndicators(objects);
      const createdRelationships = await Promise.all(
        resolvedIndicators.map((indicator) => {
          const values = {
            relationship_type: 'indicates',
            confidence: container.confidence,
            fromId: indicator.id,
            toId: selectedEntity[type],
            createdBy: container.createdBy?.id,
            objectMarking: container.objectMarking.map((m) => m.id),
          };
          return new Promise((resolve) => {
            commitMutation({
              mutation: stixCoreRelationshipCreationMutation,
              variables: {
                input: values,
              },
              onCompleted: (response) => resolve(response.stixCoreRelationshipAdd),
            });
          });
        }),
      );
      await Promise.all(
        createdRelationships.map((createdRelationship) => {
          const input = {
            toId: createdRelationship.id,
            relationship_type: 'object',
          };
          return new Promise((resolve) => {
            commitMutation({
              mutation: containerAddStixCoreObjectsLinesRelationAddMutation,
              variables: {
                id: container.id,
                input,
              },
              onCompleted: (response) => resolve(response.containerEdit.relationAdd),
            });
          });
        }),
      );
      MESSAGING$.notifySuccess('Suggestion successfully applied.');
      setAppliedSuggestion(type);
      setApplied([
        ...applied,
        {
          [type]: selectedEntity[type],
        },
      ]);
      setApplying(applying.filter((n) => n !== type));
      if (onApplied) {
        return onApplied(createdRelationships);
      }
    }
    if (type === 'threats-arsenal' && selectedEntity) {
      // create all targets relationships
      setApplying([...applying, type]);
      const selectedObjectType = objects
        .filter((n) => n.id === selectedEntity[type])
        .at(0).entity_type;
      const resolvedArsenal = resolveArsenal(objects).filter(
        (n) => n.entity_type !== selectedObjectType,
      );
      const createdRelationships = await Promise.all(
        resolvedArsenal.map((arsenal) => {
          const values = {
            relationship_type: 'uses',
            confidence: container.confidence,
            fromId: selectedEntity[type],
            toId: arsenal.id,
            createdBy: container.createdBy?.id,
            objectMarking: container.objectMarking.map((m) => m.id),
          };
          return new Promise((resolve) => {
            commitMutation({
              mutation: stixCoreRelationshipCreationMutation,
              variables: {
                input: values,
              },
              onCompleted: (response) => resolve(response.stixCoreRelationshipAdd),
            });
          });
        }),
      );
      await Promise.all(
        createdRelationships.map((createdRelationship) => {
          const input = {
            toId: createdRelationship.id,
            relationship_type: 'object',
          };
          return new Promise((resolve) => {
            commitMutation({
              mutation: containerAddStixCoreObjectsLinesRelationAddMutation,
              variables: {
                id: container.id,
                input,
              },
              onCompleted: (response) => resolve(response.containerEdit.relationAdd),
            });
          });
        }),
      );
      MESSAGING$.notifySuccess('Suggestion successfully applied.');
      setAppliedSuggestion(type);
      setApplied([
        ...applied,
        {
          [type]: selectedEntity[type],
        },
      ]);
      setApplying(applying.filter((n) => n !== type));
      if (onApplied) {
        return onApplied(createdRelationships);
      }
    }
    if (type === 'threats-targets' && selectedEntity) {
      // create all targets relationships
      setApplying([...applying, type]);
      const resolvedTargets = resolveTargets(objects);
      const createdRelationships = await Promise.all(
        resolvedTargets.map((target) => {
          const values = {
            relationship_type: 'targets',
            confidence: container.confidence,
            fromId: selectedEntity[type],
            toId: target.id,
            createdBy: container.createdBy?.id,
            objectMarking: container.objectMarking.map((m) => m.id),
          };
          return new Promise((resolve) => {
            commitMutation({
              mutation: stixCoreRelationshipCreationMutation,
              variables: {
                input: values,
              },
              onCompleted: (response) => resolve(response.stixCoreRelationshipAdd),
            });
          });
        }),
      );
      await Promise.all(
        createdRelationships.map((createdRelationship) => {
          const input = {
            toId: createdRelationship.id,
            relationship_type: 'object',
          };
          return new Promise((resolve) => {
            commitMutation({
              mutation: containerAddStixCoreObjectsLinesRelationAddMutation,
              variables: {
                id: container.id,
                input,
              },
              onCompleted: (response) => resolve(response.containerEdit.relationAdd),
            });
          });
        }),
      );
      MESSAGING$.notifySuccess('Suggestion successfully applied.');
      setAppliedSuggestion(type);
      setApplied([
        ...applied,
        {
          [type]: selectedEntity[type],
        },
      ]);
      setApplying(applying.filter((n) => n !== type));
      if (onApplied) {
        return onApplied(createdRelationships);
      }
    }
  };

  const settingsMessagesBannerHeight = useSettingsMessagesBannerHeight();
  // containerDefault style
  let containerStyle = {
    marginTop: 0,
  };
  if (knowledge || currentMode === 'graph' || currentMode === 'correlation') {
    // container knowledge / graph style
    containerStyle = {
      position: 'absolute',
      top: 165 + settingsMessagesBannerHeight,
      right: 24,
    };
  }

  const triggersPaginationOptions = {
    includeAuthorities: true,
    filters: {
      mode: 'and',
      filterGroups: [],
      filters: [
        {
          key: ['filters'],
          values: [container.id],
          operator: 'match',
          mode: 'or',
        },
        {
          key: ['instance_trigger'],
          values: ['true'],
          operator: 'eq',
          mode: 'or',
        },
      ],
    },
  };
  const triggerData = useLazyLoadQuery(stixCoreObjectQuickSubscriptionContentQuery, { first: 20, ...triggersPaginationOptions });
  return (
    <Box sx={containerStyle}>
      <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
        {!knowledge && (
          <Tooltip
            title={
              container.name
              || container.attribute_abstract
              || container.content
              || container.opinion
              || `${fd(container.first_observed)} - ${fd(container.last_observed)}`
            }
          >
            <Typography
              variant="h1"
              gutterBottom={true}
              classes={{ root: classes.title }}
            >
              {truncate(
                container.name
                || container.attribute_abstract
                || container.content
                || container.opinion
                || `${fd(container.first_observed)} - ${fd(
                  container.last_observed,
                )}`,
                80,
              )}
            </Typography>
          </Tooltip>
        )}
        {knowledge && (
          <div className={classes.export}>
            <ExportButtons
              domElementId="container"
              name={t_i18n('Report representation')}
              pixelRatio={currentMode === 'graph' ? 1 : 2}
              adjust={adjust}
              containerId={container.id}
              investigationAddFromContainer={investigationAddFromContainer}
            />
          </div>
        )}
        {modes && (
          <div className={classes.modes}>
            <ToggleButtonGroup size="small" exclusive={true}>
              {modes.includes('graph') && (
                <Tooltip title={t_i18n('Graph view')}>
                  <ToggleButton
                    component={Link}
                    to={`${link}/graph`}
                    selected={currentMode === 'graph'}
                  >
                    <VectorPolygon
                      fontSize="small"
                      color={currentMode === 'graph' ? 'primary' : 'inherit'}
                    />
                  </ToggleButton>
                </Tooltip>
              )}
              {!contentMappingFeatureFlag && modes.includes('content') && (
                <Tooltip title={t_i18n('Content mapping view')}>
                  <ToggleButton
                    component={Link}
                    to={`${link}/content`}
                    selected={currentMode === 'content'}
                  >
                    <DifferenceOutlined
                      fontSize="small"
                      color={currentMode === 'content' ? 'primary' : 'inherit'}
                    />
                  </ToggleButton>
                </Tooltip>
              )}
              {modes.includes('timeline') && (
                <Tooltip title={t_i18n('TimeLine view')}>
                  <ToggleButton
                    component={Link}
                    to={`${link}/timeline`}
                    selected={currentMode === 'timeline'}
                  >
                    <ChartTimeline
                      fontSize="small"
                      color={currentMode === 'timeline' ? 'primary' : 'inherit'}
                    />
                  </ToggleButton>
                </Tooltip>
              )}
              {modes.includes('correlation') && (
                <Tooltip title={t_i18n('Correlation view')}>
                  <ToggleButton
                    component={Link}
                    to={`${link}/correlation`}
                    selected={currentMode === 'correlation'}
                  >
                    <VectorLink
                      fontSize="small"
                      color={
                        currentMode === 'correlation' ? 'primary' : 'inherit'
                      }
                    />
                  </ToggleButton>
                </Tooltip>
              )}
              {modes.includes('matrix') && (
                <Tooltip title={t_i18n('Tactics matrix view')}>
                  <ToggleButton
                    component={Link}
                    to={`${link}/matrix`}
                    selected={currentMode === 'matrix'}
                  >
                    <ViewColumnOutlined
                      fontSize="small"
                      color={currentMode === 'matrix' ? 'primary' : 'inherit'}
                    />
                  </ToggleButton>
                </Tooltip>
              )}
            </ToggleButtonGroup>
          </div>
        )}
        <div className={classes.actions}>
          <div className={classes.actionButtons}>
            {enableQuickSubscription && (
              <StixCoreObjectSubscribers triggerData={triggerData} />
            )}
            <Security
              needs={[KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS]}
              hasAccess={!!enableManageAuthorizedMembers}
            >
              <FormAuthorizedMembersDialog
                id={container.id}
                owner={container.creators?.[0]}
                authorizedMembers={authorizedMembersToOptions(
                  container.authorized_members,
                )}
                mutation={authorizedMembersMutation}
              />
            </Security>
            {!knowledge && disableSharing !== true && (
              <StixCoreObjectSharing elementId={container.id} variant="header" />
            )}
            {!knowledge && (
              <StixCoreObjectFileExport
                id={container.id}
                type={container.entity_type}
                redirectToContent={!!redirectToContent}
              />
            )}
            {enableSuggestions && (
              <QueryRenderer
                query={containerHeaderObjectsQuery}
                variables={{ id: container.id }}
                render={({ props: containerProps }) => {
                  if (containerProps && containerProps.container) {
                    const suggestions = generateSuggestions(
                      containerProps.container.objects.edges.map((o) => ({
                        ...o.node,
                        types: o.types,
                      })),
                    );
                    const appliedSuggestions = getAppliedSuggestions();
                    if (userIsKnowledgeEditor) {
                      return (
                        <>
                          <Tooltip title={t_i18n('Open the suggestions')}>
                            <ToggleButton
                              onClick={() => setDisplaySuggestions(true)}
                              disabled={
                                suggestions.length === 0
                                || currentMode !== 'graph'
                              }
                              value="suggestion"
                              size="small"
                            >
                              <Badge
                                badgeContent={
                                  suggestions.filter(
                                    (n) => !appliedSuggestions.includes(n.type),
                                  ).length
                                }
                                color="secondary"
                              >
                                <AssistantOutlined
                                  fontSize="small"
                                  disabled={suggestions.length === 0}
                                  color={
                                    // eslint-disable-next-line no-nested-ternary
                                    suggestions.length === 0
                                      ? 'disabled'
                                      : displaySuggestions
                                        ? 'secondary'
                                        : 'primary'
                                  }
                                />
                              </Badge>
                            </ToggleButton>
                          </Tooltip>
                          <Dialog
                            PaperProps={{ elevation: 1 }}
                            open={displaySuggestions}
                            TransitionComponent={Transition}
                            onClose={() => setDisplaySuggestions(false)}
                            maxWidth="md"
                            fullWidth={true}
                          >
                            <DialogTitle>{t_i18n('Suggestions')}</DialogTitle>
                            <DialogContent dividers={true}>
                              <List>
                                {suggestions.map((suggestion) => (
                                  <ListItem
                                    key={suggestion.type}
                                    disableGutters={true}
                                    divider={true}
                                  >
                                    <ListItemText
                                      primary={
                                        <MarkdownDisplay
                                          content={t_i18n(
                                            `suggestion_${suggestion.type}`,
                                          )}
                                          remarkGfmPlugin={true}
                                          commonmark={true}
                                          markdownComponents={true}
                                        />
                                      }
                                    />
                                    <Select
                                      style={{
                                        width: 200,
                                        minWidth: 200,
                                        margin: '0 0 0 15px',
                                      }}
                                      variant="standard"
                                      onChange={(event) => handleSelectEntity(suggestion.type, event)
                                      }
                                      value={selectedEntity[suggestion.type]}
                                    >
                                      {suggestion.data.map((object) => (
                                        <MenuItem
                                          key={object.id}
                                          value={object.id}
                                        >
                                          {getMainRepresentative(object)}
                                        </MenuItem>
                                      ))}
                                    </Select>
                                    <ListItemSecondaryAction>
                                      <IconButton
                                        edge="end"
                                        aria-label="apply"
                                        onClick={() => applySuggestion(
                                          suggestion.type,
                                          containerProps.container.objects.edges.map(
                                            (o) => ({
                                              ...o.node,
                                              types: o.types,
                                            }),
                                          ),
                                        )
                                        }
                                        size="large"
                                        color={
                                          applied.some(
                                            (a) => a[suggestion.type]
                                              === selectedEntity[suggestion.type],
                                          )
                                            ? 'success'
                                            : 'secondary'
                                        }
                                        disabled={
                                          applying.includes(suggestion.type)
                                          || !selectedEntity[suggestion.type]
                                        }
                                      >
                                        {applying.includes(suggestion.type) ? (
                                          <CircularProgress
                                            size={20}
                                            color="inherit"
                                          />
                                        ) : (
                                          <AddTaskOutlined />
                                        )}
                                      </IconButton>
                                    </ListItemSecondaryAction>
                                  </ListItem>
                                ))}
                              </List>
                            </DialogContent>
                            <DialogActions>
                              <Button
                                onClick={() => setDisplaySuggestions(false)}
                                color="primary"
                              >
                                {t_i18n('Close')}
                              </Button>
                            </DialogActions>
                          </Dialog>
                        </>
                      );
                    }
                  }
                  return <div />;
                }}
              />
            )}
            {enableQuickSubscription && (
              <StixCoreObjectQuickSubscription
                instanceId={container.id}
                instanceName={getMainRepresentative(container)}
                paginationOptions={triggersPaginationOptions}
                triggerData={triggerData}
              />
            )}
            {enableAskAi && (
              <StixCoreObjectAskAI
                instanceId={container.id}
                instanceType={container.entity_type}
                instanceName={getMainRepresentative(container)}
                instanceMarkings={container.objectMarking.map(({ id }) => id)}
                type="container"
              />
            )}
            {!knowledge && (
              <Security needs={popoverSecurity || [KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNENRICHMENT]}>
                {React.cloneElement(PopoverComponent, { id: container.id })}
              </Security>
            )}
          </div>
        </div>
        <div className="clearfix" />
      </React.Suspense>
    </Box>
  );
};

export default createFragmentContainer(ContainerHeader, {
  container: graphql`
    fragment ContainerHeader_container on Container {
      id
      entity_type
      standard_id
      confidence
      created
      ... on Report {
        name
      }
      ... on Grouping {
        name
      }
      ... on Case {
        name
      }
      ... on Feedback {
        name
      }
      ... on Task {
        name
      }
      ... on CaseIncident {
        name
      }
      ... on CaseRfi {
        name
      }
      ... on CaseRft {
        name
      }
      ... on Note {
        attribute_abstract
        content
      }
      ... on Opinion {
        opinion
      }
      ... on ObservedData {
        name
        first_observed
        last_observed
      }
      createdBy {
        id
      }
      objectMarking {
        id
        definition_type
        definition
        x_opencti_order
        x_opencti_color
      }
    }
  `,
});
