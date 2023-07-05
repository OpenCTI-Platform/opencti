import React, { useState } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import Typography from '@mui/material/Typography';
import { Link } from 'react-router-dom';
import Tooltip from '@mui/material/Tooltip';
import { ChartTimeline, GraphOutline, VectorLink } from 'mdi-material-ui';
import {
  AddTaskOutlined,
  AssistantOutlined,
  DifferenceOutlined,
  ViewColumnOutlined,
} from '@mui/icons-material';
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
import Slide from '@mui/material/Slide';
import Select from '@mui/material/Select';
import MenuItem from '@mui/material/MenuItem';
import CircularProgress from '@mui/material/CircularProgress';
import { makeStyles } from '@mui/styles';
import ExportButtons from '../../../../components/ExportButtons';
import Security from '../../../../utils/Security';
import { useFormatter } from '../../../../components/i18n';
import { truncate } from '../../../../utils/String';
import {
  commitMutation,
  MESSAGING$,
  QueryRenderer,
} from '../../../../relay/environment';
import { defaultValue } from '../../../../utils/Graph';
import { stixCoreRelationshipCreationMutation } from '../stix_core_relationships/StixCoreRelationshipCreation';
import { containerAddStixCoreObjectsLinesRelationAddMutation } from './ContainerAddStixCoreObjectsLines';
import StixCoreObjectSharing from '../stix_core_objects/StixCoreObjectSharing';
import useGranted, {
  KNOWLEDGE_KNUPDATE,
} from '../../../../utils/hooks/useGranted';
import StixCoreObjectEnrichment from '../stix_core_objects/StixCoreObjectEnrichment';
import StixCoreObjectQuickSubscription from '../stix_core_objects/StixCoreObjectQuickSubscription';
import MarkdownDisplay from '../../../../components/MarkdownDisplay';

const useStyles = makeStyles(() => ({
  title: {
    float: 'left',
  },
  popover: {
    float: 'left',
    marginTop: '-13px',
  },
  marking: {
    float: 'left',
    overflowX: 'hidden',
    margin: '3px 0 0 15px',
  },
  modes: {
    margin: '-6px 20px 0 20px',
    float: 'right',
  },
  actions: {
    margin: '-6px 0 0 0',
    float: 'right',
  },
  organizations: {
    float: 'left',
    marginRight: 15,
    paddingTop: 2,
  },
  organization: {
    marginRight: 7,
  },
  button: {
    marginRight: 20,
  },
  export: {
    margin: '-6px 0 0 0',
    float: 'right',
  },
}));

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

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
      objectMarking {
        edges {
          node {
            id
            definition_type
            definition
            x_opencti_order
            x_opencti_color
          }
        }
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
                edges {
                  node {
                    id
                    definition_type
                    definition
                    x_opencti_order
                    x_opencti_color
                  }
                }
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
                edges {
                  node {
                    id
                    definition_type
                    definition
                    x_opencti_order
                    x_opencti_color
                  }
                }
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
                edges {
                  node {
                    id
                    definition_type
                    definition
                    x_opencti_order
                    x_opencti_color
                  }
                }
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
                edges {
                  node {
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
  } = props;
  const classes = useStyles();
  const { t, fd } = useFormatter();
  const userIsKnowledgeEditor = useGranted([KNOWLEDGE_KNUPDATE]);
  const [displaySuggestions, setDisplaySuggestions] = useState(false);
  const [selectedEntity, setSelectedEntity] = useState({});
  const [applying, setApplying] = useState([]);
  const [applied, setApplied] = useState([]);
  // Suggestions
  const resolveThreats = (objects) => objects.filter(
    (o) => [
      'Theat-Actor-Group',
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
            objectMarking: container.objectMarking.edges.map((m) => m.node.id),
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
      setApplied([...applied, type]);
      setApplying(applying.filter((n) => n !== type));
      if (onApplied) {
        return onApplied(createdRelationships);
      }
    }
    if (type === 'threats-arsenal' && selectedEntity) {
      // create all targets relationships
      setApplying([...applying, type]);
      const resolvedArsenal = resolveArsenal(objects);
      const createdRelationships = await Promise.all(
        resolvedArsenal.map((arsenal) => {
          const values = {
            relationship_type: 'uses',
            confidence: container.confidence,
            fromId: selectedEntity[type],
            toId: arsenal.id,
            createdBy: container.createdBy?.id,
            objectMarking: container.objectMarking.edges.map((m) => m.node.id),
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
      setApplied([...applied, type]);
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
            objectMarking: container.objectMarking.edges.map((m) => m.node.id),
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
      setApplied([...applied, type]);
      setApplying(applying.filter((n) => n !== type));
      if (onApplied) {
        return onApplied(createdRelationships);
      }
    }
  };
  return (
    <div>
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
      <Security needs={popoverSecurity || [KNOWLEDGE_KNUPDATE]}>
        <div className={classes.popover}>
          {React.cloneElement(PopoverComponent, { id: container.id })}
        </div>
      </Security>
      {knowledge && (
        <div className={classes.export}>
          <ExportButtons
            domElementId="container"
            name={t('Report representation')}
            pixelRatio={currentMode === 'graph' ? 1 : 2}
            adjust={adjust}
          />
        </div>
      )}
      {modes && (
        <div className={classes.modes}>
          <ToggleButtonGroup size="small" color="secondary" exclusive={true}>
            {modes.includes('graph') && (
              <Tooltip title={t('Graph view')}>
                <ToggleButton
                  component={Link}
                  to={`${link}/graph`}
                  selected={currentMode === 'graph'}
                >
                  <GraphOutline
                    fontSize="small"
                    color={currentMode === 'graph' ? 'secondary' : 'primary'}
                  />
                </ToggleButton>
              </Tooltip>
            )}
            {modes.includes('content') && (
              <Tooltip title={t('Content mapping view')}>
                <ToggleButton
                  component={Link}
                  to={`${link}/content`}
                  selected={currentMode === 'content'}
                >
                  <DifferenceOutlined
                    fontSize="small"
                    color={currentMode === 'content' ? 'secondary' : 'primary'}
                  />
                </ToggleButton>
              </Tooltip>
            )}
            {modes.includes('timeline') && (
              <Tooltip title={t('TimeLine view')}>
                <ToggleButton
                  component={Link}
                  to={`${link}/timeline`}
                  selected={currentMode === 'timeline'}
                >
                  <ChartTimeline
                    fontSize="small"
                    color={currentMode === 'timeline' ? 'secondary' : 'primary'}
                  />
                </ToggleButton>
              </Tooltip>
            )}
            {modes.includes('correlation') && (
              <Tooltip title={t('Correlation view')}>
                <ToggleButton
                  component={Link}
                  to={`${link}/correlation`}
                  selected={currentMode === 'correlation'}
                >
                  <VectorLink
                    fontSize="small"
                    color={
                      currentMode === 'correlation' ? 'secondary' : 'primary'
                    }
                  />
                </ToggleButton>
              </Tooltip>
            )}
            {modes.includes('matrix') && (
              <Tooltip title={t('Tactics matrix view')}>
                <ToggleButton
                  component={Link}
                  to={`${link}/matrix`}
                  selected={currentMode === 'matrix'}
                >
                  <ViewColumnOutlined
                    fontSize="small"
                    color={currentMode === 'matrix' ? 'secondary' : 'primary'}
                  />
                </ToggleButton>
              </Tooltip>
            )}
          </ToggleButtonGroup>
        </div>
      )}
      <div className={classes.actions}>
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
                  <React.Fragment>
                    <ToggleButtonGroup
                      size="small"
                      color="secondary"
                      exclusive={false}
                    >
                      {disableSharing !== true && (
                        <StixCoreObjectSharing
                          elementId={container.id}
                          variant="header"
                        />
                      )}
                      {enableSuggestions && (
                        <React.Fragment>
                          <Tooltip title={t('Open the suggestions')}>
                            <ToggleButton
                              onClick={() => setDisplaySuggestions(true)}
                              disabled={suggestions.length === 0}
                              value="suggestion"
                              size="small"
                              style={{ marginRight: 3 }}
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
                        </React.Fragment>
                      )}
                      {enableQuickSubscription && (
                        <StixCoreObjectQuickSubscription
                          instanceId={container.id}
                          instanceName={defaultValue(container)}
                        />
                      )}
                      <StixCoreObjectEnrichment
                        stixCoreObjectId={container.id}
                      />
                    </ToggleButtonGroup>
                    <Dialog
                      PaperProps={{ elevation: 1 }}
                      open={displaySuggestions}
                      TransitionComponent={Transition}
                      onClose={() => setDisplaySuggestions(false)}
                      maxWidth="md"
                      fullWidth={true}
                    >
                      <DialogTitle>{t('Suggestions')}</DialogTitle>
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
                                    content={t(`suggestion_${suggestion.type}`)}
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
                                  <MenuItem key={object.id} value={object.id}>
                                    {defaultValue(object)}
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
                                    applied.includes(suggestion.type)
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
                          {t('Close')}
                        </Button>
                      </DialogActions>
                    </Dialog>
                  </React.Fragment>
                );
              }
            }
            return <div />;
          }}
        />
      </div>
      <div className="clearfix" />
    </div>
  );
};

export default createFragmentContainer(ContainerHeader, {
  container: graphql`
    fragment ContainerHeader_container on Container {
      id
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
        edges {
          node {
            id
            definition_type
            definition
            x_opencti_order
            x_opencti_color
          }
        }
      }
    }
  `,
});
