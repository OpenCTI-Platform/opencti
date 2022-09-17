import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import withTheme from '@mui/styles/withTheme';
import Typography from '@mui/material/Typography';
import { Link } from 'react-router-dom';
import Tooltip from '@mui/material/Tooltip';
import { GraphOutline, VectorLink } from 'mdi-material-ui';
import {
  AddTaskOutlined,
  ViewColumnOutlined,
  AssistantOutlined,
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
import remarkGfm from 'remark-gfm';
import remarkParse from 'remark-parse';
import Markdown from 'react-markdown';
import CircularProgress from '@mui/material/CircularProgress';
import ExportButtons from '../../../../components/ExportButtons';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';
import ItemMarking from '../../../../components/ItemMarking';
import inject18n from '../../../../components/i18n';
import { truncate } from '../../../../utils/String';
import {
  commitMutation,
  MESSAGING$,
  QueryRenderer,
} from '../../../../relay/environment';
import { defaultValue } from '../../../../utils/Graph';
import { stixCoreRelationshipCreationMutation } from '../stix_core_relationships/StixCoreRelationshipCreation';
import { MarkDownComponents } from '../../../../components/ExpandableMarkdown';
import { containerAddStixCoreObjectsLinesRelationAddMutation } from './ContainerAddStixCoreObjectsLines';

const styles = () => ({
  title: {
    float: 'left',
    textTransform: 'uppercase',
  },
  popover: {
    float: 'left',
    marginTop: '-13px',
  },
  marking: {
    float: 'left',
    overflowX: 'hidden',
    marginLeft: 15,
  },
  aliases: {
    marginRight: 7,
  },
  aliasesInput: {
    margin: '4px 0 0 10px',
    float: 'right',
  },
  modes: {
    margin: '-6px 20px 0 20px',
    float: 'right',
  },
  suggestions: {
    margin: '-6px 0 0 0',
    float: 'right',
  },
  button: {
    marginRight: 20,
  },
  export: {
    margin: '-6px 0 0 0',
    float: 'right',
  },
});

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
            definition
          }
        }
      }
      objects(all: true) {
        edges {
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
                    definition
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
            ... on StixCyberObservable {
              observable_value
            }
            ... on StixFile {
              observableName: name
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
                    definition
                  }
                }
              }
            }
            ... on StixCyberObservableRelationship {
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
                    definition
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
                    definition
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

class ContainerHeaderComponent extends Component {
  constructor(props) {
    super(props);
    this.state = {
      displaySuggestions: false,
      selectedEntity: {},
      applying: [],
      applied: [],
    };
  }

  handleOpenSuggestions() {
    this.setState({ displaySuggestions: true });
  }

  handleCloseSuggestions() {
    this.setState({ displaySuggestions: false });
  }

  // eslint-disable-next-line class-methods-use-this
  resolveThreats(objects) {
    return objects.filter((o) => [
      'Threat-Actor',
      'Intrusion-Set',
      'Campaign',
      'Incident',
      'Malware',
      'Tool',
    ].includes(o.entity_type));
  }

  // eslint-disable-next-line class-methods-use-this
  resolveIndicators(objects) {
    return objects.filter((o) => ['Indicator'].includes(o.entity_type));
  }

  generateSuggestions(objects) {
    const suggestions = [];
    const resolvedThreats = this.resolveThreats(objects);
    // First rule, threats and indicators
    if (
      resolvedThreats.length > 0
      && objects.filter((o) => o.entity_type === 'Indicator').length > 0
    ) {
      suggestions.push({ type: 'threats-indicators', data: resolvedThreats });
    }
    return suggestions;
  }

  handleSelectEntity(type, event) {
    if (event && event.target && event.target.value) {
      const { selectedEntity } = this.state;
      this.setState({
        selectedEntity: { ...selectedEntity, [type]: event.target.value },
      });
    }
  }

  async applySuggestion(type, objects) {
    const { selectedEntity } = this.state;
    const { container } = this.props;
    if (type === 'threats-indicators' && selectedEntity) {
      // create all indicates relationships
      this.setState({ applying: [...this.state.applying, type] });
      const indicators = this.resolveIndicators(objects);
      const createdRelationships = await Promise.all(
        indicators.map((indicator) => {
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
      localStorage.setItem(`suggestions-${container.id}`, [
        ...(localStorage.getItem(`suggestions-${container.id}`) || []),
        type,
      ]);
      if (this.props.onApplied) {
        this.props.onApplied();
      }
      this.setState({
        applied: [...this.state.applied, type],
        applying: this.state.applying.filter((n) => n !== type),
      });
    }
  }

  render() {
    const {
      classes,
      container,
      variant,
      PopoverComponent,
      fd,
      link,
      modes,
      currentMode,
      knowledge,
      adjust,
      t,
      theme,
      enableSuggestions,
    } = this.props;
    const { displaySuggestions, selectedEntity, applying, applied } = this.state;
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
        {variant !== 'noMarking' && (
          <div className={classes.marking}>
            {R.pathOr([], ['objectMarking', 'edges'], container).map(
              (markingDefinition) => (
                <ItemMarking
                  key={markingDefinition.node.id}
                  label={markingDefinition.node.definition}
                  color={markingDefinition.node.x_opencti_color}
                />
              ),
            )}
          </div>
        )}
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
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
        {enableSuggestions && (
          <QueryRenderer
            query={containerHeaderObjectsQuery}
            variables={{ id: container.id }}
            render={({ props }) => {
              if (props && props.container) {
                const suggestions = this.generateSuggestions(
                  props.container.objects.edges.map((o) => o.node),
                );
                const appliedSuggestions = localStorage.getItem(`suggestions-${container.id}`) || [];
                return (
                  <div className={classes.suggestions}>
                    <Security needs={[KNOWLEDGE_KNUPDATE]}>
                      <ToggleButtonGroup
                        size="small"
                        color="secondary"
                        exclusive={true}
                      >
                        <Tooltip title={t('Open suggestions')}>
                          <ToggleButton
                            onClick={this.handleOpenSuggestions.bind(this)}
                            disabled={suggestions.length === 0}
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
                      </ToggleButtonGroup>
                    </Security>
                    <Dialog
                      PaperProps={{ elevation: 1 }}
                      open={displaySuggestions}
                      TransitionComponent={Transition}
                      onClose={this.handleCloseSuggestions.bind(this)}
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
                                  <Markdown
                                    remarkPlugins={[remarkGfm, remarkParse]}
                                    parserOptions={{ commonmark: true }}
                                    components={MarkDownComponents(theme)}
                                    className="markdown"
                                  >
                                    {t(`suggestion_${suggestion.type}`)}
                                  </Markdown>
                                }
                              />
                              <Select
                                style={{ width: 200, margin: '0 0 0 15px' }}
                                variant="standard"
                                onChange={this.handleSelectEntity.bind(
                                  this,
                                  suggestion.type,
                                )}
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
                                  onClick={this.applySuggestion.bind(
                                    this,
                                    suggestion.type,
                                    props.container.objects.edges.map(
                                      (o) => o.node,
                                    ),
                                  )}
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
                          onClick={this.handleCloseSuggestions.bind(this)}
                          color="primary"
                        >
                          {t('Close')}
                        </Button>
                      </DialogActions>
                    </Dialog>
                  </div>
                );
              }
              return <div />;
            }}
          />
        )}
        <div className="clearfix" />
      </div>
    );
  }
}

ContainerHeaderComponent.propTypes = {
  container: PropTypes.object,
  PopoverComponent: PropTypes.object,
  variant: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
  link: PropTypes.string,
  modes: PropTypes.array,
  currentMode: PropTypes.string,
  knowledge: PropTypes.bool,
  adjust: PropTypes.func,
  onApplied: PropTypes.func,
};

const ContainerHeader = createFragmentContainer(ContainerHeaderComponent, {
  container: graphql`
    fragment ContainerHeader_container on Container {
      id
      confidence
      created
      ... on Report {
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
            definition
            x_opencti_color
          }
        }
      }
    }
  `,
});

export default R.compose(
  inject18n,
  withTheme,
  withStyles(styles),
)(ContainerHeader);
