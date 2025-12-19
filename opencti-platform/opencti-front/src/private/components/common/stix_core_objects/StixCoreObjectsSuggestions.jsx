import React, { useState } from 'react';
import Button from '@common/button/Button';
import {
  Badge,
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  IconButton,
  List,
  ListItem,
  ListItemText,
  MenuItem,
  Select,
  ToggleButton,
  Tooltip,
} from '@mui/material';
import { AddTaskOutlined, AssistantOutlined } from '@mui/icons-material';
import { useTheme } from '@mui/styles';
import { getMainRepresentative } from '../../../../utils/defaultRepresentatives';
import { commitMutation, MESSAGING$, QueryRenderer } from '../../../../relay/environment';
import { stixCoreRelationshipCreationMutation } from '../stix_core_relationships/StixCoreRelationshipCreation';
import { containerAddStixCoreObjectsLinesRelationAddMutation } from '../containers/ContainerAddStixCoreObjectsLines';
import MarkdownDisplay from '../../../../components/MarkdownDisplay';
import Transition from '../../../../components/Transition';
import { useFormatter } from '../../../../components/i18n';
import useGranted, { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';

const StixCoreObjectsSuggestionsComponent = (props) => {
  const { t_i18n } = useFormatter();
  const {
    container,
    currentMode,
    onApplied,
    containerHeaderObjectsQuery,
  } = props;
  const theme = useTheme();
  const userIsKnowledgeEditor = useGranted([KNOWLEDGE_KNUPDATE]);
  const [displaySuggestions, setDisplaySuggestions] = useState(false);
  const [selectedEntity, setSelectedEntity] = useState({});
  const [applying, setApplying] = useState([]);
  const [applied, setApplied] = useState([]);
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
  return (
    <>
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
                <div style={{ marginLeft: theme.spacing(2) }}>
                  <Tooltip title={t_i18n('Open the suggestions')}>
                    <ToggleButton
                      onClick={() => setDisplaySuggestions(true)}
                      disabled={
                        suggestions.length === 0 || currentMode !== 'graph'
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
                    slotProps={{ paper: { elevation: 1 } }}
                    open={displaySuggestions}
                    slots={{ transition: Transition }}
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
                            secondaryAction={(
                              <Tooltip title={t_i18n('Apply the suggestion')}>
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
                                  color={
                                    applied.some(
                                      (a) => a[suggestion.type]
                                        === selectedEntity[suggestion.type],
                                    )
                                      ? 'success'
                                      : 'primary'
                                  }
                                  disabled={
                                    applying.includes(suggestion.type)
                                    || !selectedEntity[suggestion.type]
                                  }
                                >
                                  {applying.includes(suggestion.type) ? (
                                    <CircularProgress size={20} color="inherit" />
                                  ) : (
                                    <AddTaskOutlined />
                                  )}
                                </IconButton>
                              </Tooltip>
                            )}
                          >
                            <ListItemText
                              primary={(
                                <MarkdownDisplay
                                  content={t_i18n(`suggestion_${suggestion.type}`)}
                                  remarkGfmPlugin={true}
                                  commonmark={true}
                                  markdownComponents={true}
                                />
                              )}
                            />
                            <Select
                              style={{ width: 200, minWidth: 200, margin: '0 0 0 15px' }}
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
                          </ListItem>
                        ))}
                      </List>
                    </DialogContent>
                    <DialogActions>
                      <Button
                        onClick={() => setDisplaySuggestions(false)}
                      >
                        {t_i18n('Close')}
                      </Button>
                    </DialogActions>
                  </Dialog>
                </div>
              );
            }
          }
          return <div />;
        }}
      />
    </>
  );
};

export default StixCoreObjectsSuggestionsComponent;
