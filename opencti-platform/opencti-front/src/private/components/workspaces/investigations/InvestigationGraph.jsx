import Dialog from '@mui/material/Dialog';
import withTheme from '@mui/styles/withTheme';
import PropTypes from 'prop-types';
import * as R from 'ramda';
import React, { Component } from 'react';
import ForceGraph2D from 'react-force-graph-2d';
import ForceGraph3D from 'react-force-graph-3d';
import RectangleSelection from 'react-rectangle-selection';
import { createFragmentContainer, graphql } from 'react-relay';
import { Subject, timer } from 'rxjs';
import { debounce } from 'rxjs/operators';
import SpriteText from 'three-spritetext';
import { getPreExpansionStateList, investigationPreExpansionStateListStorageKey, updatePreExpansionStateList } from './utils/investigationStorage';
import InvestigationRollBackExpandDialog from './Dialog/InvestigationRollBackExpandDialog';
import withRouter from '../../../../utils/compat-router/withRouter';
import InvestigationExpandForm from './InvestigationExpandForm';
import inject18n from '../../../../components/i18n';
import { commitMutation, fetchQuery, MESSAGING$ } from '../../../../relay/environment';
import { hexToRGB } from '../../../../utils/Colors';
import setStackDataInSessionStorage from './utils/setStackDataInSessionStorage/setStackDataInSessionStorage';
import {
  applyFilters,
  buildGraphData,
  computeTimeRangeInterval,
  computeTimeRangeValues,
  decodeGraphData,
  encodeGraphData,
  linkPaint,
  nodeAreaPaint,
  nodePaint,
  nodeThreePaint,
} from '../../../../utils/Graph';
import { getSecondaryRepresentative, getMainRepresentative } from '../../../../utils/defaultRepresentatives';
import EntitiesDetailsRightsBar from '../../../../utils/graph/EntitiesDetailsRightBar';
import LassoSelection from '../../../../utils/graph/LassoSelection';
import { buildViewParamsFromUrlAndStorage, saveViewParameters } from '../../../../utils/ListParameters';
import { workspaceMutationFieldPatch } from '../WorkspaceEditionOverview';
import WorkspaceHeader from '../WorkspaceHeader';
import InvestigationGraphBar from './InvestigationGraphBar';
import { UserContext } from '../../../../utils/hooks/useAuth';
import { investigationAddStixCoreObjectsLinesRelationsDeleteMutation } from './InvestigationAddStixCoreObjectsLines';
import { isNotEmptyField } from '../../../../utils/utils';
import RelationSelection from '../../../../utils/graph/RelationSelection';

const PARAMETERS$ = new Subject().pipe(debounce(() => timer(2000)));
const POSITIONS$ = new Subject().pipe(debounce(() => timer(2000)));
const DBL_CLICK_TIMEOUT = 500; // ms

export const investigationGraphQuery = graphql`
  query InvestigationGraphQuery($id: String!) {
    workspace(id: $id) {
      ...InvestigationGraph_workspace
    }
  }
`;

const investigationGraphStixCoreObjectQuery = graphql`
  query InvestigationGraphStixCoreObjectQuery($id: String!) {
    stixCoreObject(id: $id) {
      id
      entity_type
      parent_types
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
      ... on Channel {
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
      }
      ... on Event {
        name
      }
      ... on Case {
        name
      }
      ... on Narrative {
        name
      }
      ... on DataComponent {
        name
      }
      ... on DataSource {
        name
      }
      ... on Language {
        name
      }
    }
  }
`;

const investigationGraphStixCoreRelationshipQuery = graphql`
  query InvestigationGraphStixCoreRelationshipQuery($id: String!) {
    stixCoreRelationship(id: $id) {
      id
      entity_type
      parent_types
      start_time
      stop_time
      confidence
      relationship_type
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
      updated_at
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
`;

const investigationGraphStixSightingRelationshipQuery = graphql`
  query InvestigationGraphStixSightingRelationshipQuery($id: String!) {
    stixSightingRelationship(id: $id) {
      id
      entity_type
      parent_types
      first_seen
      last_seen
      confidence
      relationship_type
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
      updated_at
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
`;

// To count the number of relationships for MetaObjects and Identities.
//
// /!\ It counts only rels that point towards given ids. So the value may not be
// exactly the total number of rels in some cases when entities (Identities) also
// have relations where there are the source of the relation.
// This issue can be fixed by making a second query fetching the count in the
// other direction. TODO Call this query.
const investigationGraphCountRelToQuery = graphql`
  query InvestigationGraphStixCountRelToQuery($objectIds: [String!]!) {
    stixRelationshipsDistribution(
      field: "internal_id"
      isTo: true
      operation: count
      toId: $objectIds
      relationship_type: "stix-relationship"
    ) {
      label
      value
    }
  }
`;

const investigationGraphStixRelationshipsQuery = graphql`
  query InvestigationGraphStixRelationshipsQuery(
    $filters: FilterGroup
  ) {
    stixRelationships(
      filters: $filters
    ) {
      edges {
        node {
          id
          entity_type
          parent_types
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

const investigationGraphRelationsAddMutation = graphql`
  mutation InvestigationGraphRelationsAddMutation(
    $id: ID!
    $input: [EditInput!]!
  ) {
    workspaceFieldPatch(id: $id, input: $input) {
      id
    }
  }
`;
class InvestigationGraphComponent extends Component {
  constructor(props) {
    const LOCAL_STORAGE_KEY = `workspace-${props.workspace.id}-investigation`;
    super(props);
    this.initialized = false;
    this.zoomed = 0;
    this.graph = React.createRef();
    this.selectedNodes = new Set();
    this.selectedLinks = new Set();
    const params = buildViewParamsFromUrlAndStorage(
      props.navigate,
      props.location,
      LOCAL_STORAGE_KEY,
    );
    this.zoom = R.propOr(null, 'zoom', params);
    this.graphObjects = R.map((n) => n.node, props.workspace.objects.edges);
    this.graphData = buildGraphData(
      this.graphObjects,
      decodeGraphData(props.workspace.graph_data),
      props.t,
    );
    const sortByLabel = R.sortBy(R.compose(R.toLower, R.prop('tlabel')));
    const sortByDefinition = R.sortBy(
      R.compose(R.toLower, R.prop('definition')),
    );
    const sortByName = R.sortBy(R.compose(R.toLower, R.prop('name')));
    const allStixCoreObjectsTypes = R.pipe(
      R.map((n) => n.entity_type),
      R.uniq,
      R.map((n) => ({
        label: n,
        tlabel: props.t(
          `${n.relationship_type ? 'relationship_' : 'entity_'}${
            n.entity_type
          }`,
        ),
      })),
      sortByLabel,
      R.map((n) => n.label),
    )(this.graphData.nodes);
    const allMarkedBy = R.pipe(
      R.map((n) => n.markedBy),
      R.flatten,
      R.uniqBy(R.prop('id')),
      sortByDefinition,
    )(R.union(this.graphData.nodes, this.graphData.links));
    const allCreatedBy = R.pipe(
      R.map((n) => n.createdBy),
      R.uniqBy(R.prop('id')),
      sortByName,
    )(R.union(this.graphData.nodes, this.graphData.links));
    const stixCoreObjectsTypes = R.propOr([], 'stixCoreObjectsTypes', params);
    const markedBy = R.propOr([], 'objectMarking', params);
    const createdBy = R.propOr([], 'createdBy', params);
    const timeRangeInterval = computeTimeRangeInterval(this.graphObjects);

    this.fetchObjectRelCounts(this.graphObjects);

    this.state = {
      mode3D: R.propOr(false, 'mode3D', params),
      selectRectangleModeFree: R.propOr(
        false,
        'selectRectangleModeFree',
        params,
      ),
      selectModeFree: params.selectModeFree ?? false,
      selectModeFreeReady: false,
      modeFixed: R.propOr(false, 'modeFixed', params),
      modeTree: R.propOr('', 'modeTree', params),
      displayTimeRange: R.propOr(false, 'displayTimeRange', params),
      rectSelected: {
        origin: [0, 0],
        target: [0, 0],
        shiftKey: false,
        altKey: false,
      },
      selectedTimeRangeInterval: timeRangeInterval,
      allStixCoreObjectsTypes,
      allMarkedBy,
      allCreatedBy,
      stixCoreObjectsTypes,
      markedBy,
      createdBy,
      graphData: applyFilters(
        this.graphData,
        stixCoreObjectsTypes,
        markedBy,
        createdBy,
        [],
        timeRangeInterval,
      ),
      numberOfSelectedNodes: 0,
      numberOfSelectedLinks: 0,
      displayProgress: false,
      width: null,
      height: null,
      zoomed: false,
      keyword: '',
      prevClick: null,
      navOpen: localStorage.getItem('navOpen') === 'true',
      openCreatedRelation: false,
      isRollBackPreExpandStateDialogOpen: false,
    };
    this.canvas = null;
  }

  initialize() {
    if (this.initialized) return;
    if (this.graph && this.graph.current) {
      this.graph.current.d3Force('link').distance(50);
      if (this.state.modeTree !== '') {
        this.graph.current.d3Force('charge').strength(-1000);
      }
      if (this.zoomed < 2) {
        if (this.zoom && this.zoom.k && !this.state.mode3D) {
          this.graph.current.zoom(this.zoom.k, 400);
        } else {
          // eslint-disable-next-line @typescript-eslint/no-this-alias
          const currentContext = this;
          setTimeout(
            () => currentContext.graph
              && currentContext.graph.current
              && currentContext.graph.current.zoomToFit(0, 150),
            1200,
          );
        }
      }
      this.initialized = true;
      this.zoomed += 1;
      const currentCanvas = document.getElementsByTagName('canvas')[0];
      if (!this.canvas) {
        this.canvas = currentCanvas;
      }
    }
  }

  componentDidMount() {
    this.subscription1 = PARAMETERS$.subscribe({
      next: () => this.saveParameters(),
    });
    this.subscription2 = POSITIONS$.subscribe({
      next: () => this.savePositions(),
    });
    this.subscription3 = MESSAGING$.toggleNav.subscribe({
      next: () => this.setState({ navOpen: localStorage.getItem('navOpen') === 'true' }),
    });
    this.initialize();
  }

  componentWillUnmount() {
    this.subscription3.unsubscribe();
    this.subscription2.unsubscribe();
    this.subscription3.unsubscribe();
  }

  saveParameters(refreshGraphData = false) {
    const LOCAL_STORAGE_KEY = `workspace-${this.props.workspace.id}-investigation`;
    saveViewParameters(
      this.props.navigate,
      this.props.location,
      LOCAL_STORAGE_KEY,
      { zoom: this.zoom, ...this.state },
    );
    if (refreshGraphData) {
      this.setState({
        graphData: applyFilters(
          this.graphData,
          this.state.stixCoreObjectsTypes,
          this.state.markedBy,
          this.state.createdBy,
          [],
          this.state.selectedTimeRangeInterval,
        ),
      });
    }
  }

  savePositions() {
    const initialPositions = R.indexBy(
      R.prop('id'),
      R.map((n) => ({ id: n.id, x: n.fx, y: n.fy }), this.graphData.nodes),
    );
    const newPositions = R.indexBy(
      R.prop('id'),
      R.map(
        (n) => ({ id: n.id, x: n.fx, y: n.fy }),
        this.state.graphData.nodes,
      ),
    );
    const positions = R.mergeLeft(newPositions, initialPositions);
    commitMutation({
      mutation: workspaceMutationFieldPatch,
      variables: {
        id: this.props.workspace.id,
        input: {
          key: 'graph_data',
          value: encodeGraphData(positions),
        },
      },
    });
  }

  /**
   * Fetch the number of relations each meta-object and identities have
   * in the list of objects.
   *
   * (i) Why are we fetching counts only for those entities ?
   * - Fetching everything will have a cost as some entities may have
   *   a (very) lot of relationships.
   * - For other entities we use a trick by counting the number of properties
   *   starting with 'rel_' they have (data we got when retrieving objects so it's free).
   *
   * @param objects The list of objects.
   */
  async fetchObjectRelCounts(objects) {
    // Keep only meta-objects and identities.
    const objectIds = (objects ?? [])
      .filter(
        (object) => object.parent_types.includes('Stix-Meta-Object')
          || object.parent_types.includes('Identity'),
      )
      .map((object) => object.id);

    if (objectIds.length === 0) return;

    const { stixRelationshipsDistribution: relCounts } = await fetchQuery(
      investigationGraphCountRelToQuery,
      { objectIds },
    ).toPromise();

    // For each object, add the number of relations it has in our objects data.
    relCounts.forEach(({ label, value }) => {
      const object = this.graphObjects.find((obj) => obj.id === label);
      if (object) {
        this.graphObjects = [
          ...this.graphObjects.filter((obj) => obj.id !== label),
          {
            ...object,
            numberOfConnectedElement: value,
          },
        ];
      }
    });

    this.graphData = buildGraphData(
      this.graphObjects,
      decodeGraphData(this.props.workspace.graph_data),
      this.props.t,
    );
    this.setState({
      graphData: applyFilters(
        this.graphData,
        this.state.stixCoreObjectsTypes,
        this.state.markedBy,
        this.state.createdBy,
        [],
        this.state.selectedTimeRangeInterval,
      ),
    });
  }

  handleToggle3DMode() {
    this.setState({ mode3D: !this.state.mode3D }, () => this.saveParameters());
  }

  handleToggleRectangleSelectModeFree() {
    this.setState(
      {
        selectRectangleModeFree: !this.state.selectRectangleModeFree,
        selectModeFree: false,
      },
      () => {
        this.saveParameters();
      },
    );
  }

  handleToggleSelectModeFree() {
    this.setState(
      {
        selectModeFree: !this.state.selectModeFree,
        selectRectangleModeFree: false,
      },
      () => {
        this.saveParameters();
      },
    );
  }

  handleToggleTreeMode(modeTree) {
    if (modeTree === 'horizontal') {
      this.setState(
        {
          modeTree: this.state.modeTree === 'horizontal' ? '' : 'horizontal',
        },
        () => {
          if (this.state.modeTree === 'horizontal') {
            this.graph.current.d3Force('charge').strength(-1000);
          } else {
            this.graph.current.d3Force('charge').strength(-30);
          }
          this.saveParameters();
        },
      );
    } else if (modeTree === 'vertical') {
      this.setState(
        {
          modeTree: this.state.modeTree === 'vertical' ? '' : 'vertical',
        },
        () => {
          if (this.state.modeTree === 'vertical') {
            this.graph.current.d3Force('charge').strength(-1000);
          } else {
            this.graph.current.d3Force('charge').strength(-30);
          }
          this.saveParameters();
        },
      );
    }
  }

  handleToggleFixedMode() {
    this.setState({ modeFixed: !this.state.modeFixed }, () => {
      this.saveParameters();
      this.handleDragEnd();
      this.forceUpdate();
      this.graph.current.d3ReheatSimulation();
    });
  }

  handleToggleDisplayProgress() {
    this.setState({ displayProgress: !this.state.displayProgress });
  }

  handleToggleDisplayTimeRange() {
    this.setState({ displayTimeRange: !this.state.displayTimeRange }, () => this.saveParameters());
  }

  handleToggleStixCoreObjectType(type) {
    const { stixCoreObjectsTypes } = this.state;
    if (stixCoreObjectsTypes.includes(type)) {
      this.setState(
        {
          stixCoreObjectsTypes: R.filter(
            (t) => t !== type,
            stixCoreObjectsTypes,
          ),
        },
        () => this.saveParameters(true),
      );
    } else {
      this.setState(
        { stixCoreObjectsTypes: R.append(type, stixCoreObjectsTypes) },
        () => this.saveParameters(true),
      );
    }
  }

  handleToggleMarkedBy(markingDefinition) {
    const { markedBy } = this.state;
    if (markedBy.includes(markingDefinition)) {
      this.setState(
        {
          markedBy: R.filter((t) => t !== markingDefinition, markedBy),
        },
        () => this.saveParameters(true),
      );
    } else {
      // eslint-disable-next-line max-len
      this.setState({ markedBy: R.append(markingDefinition, markedBy) }, () => this.saveParameters(true));
    }
  }

  handleToggleCreateBy(createdByRef) {
    const { createdBy } = this.state;
    if (createdBy.includes(createdByRef)) {
      this.setState(
        {
          createdBy: R.filter((t) => t !== createdByRef, createdBy),
        },
        () => this.saveParameters(true),
      );
    } else {
      // eslint-disable-next-line max-len
      this.setState({ createdBy: R.append(createdByRef, createdBy) }, () => this.saveParameters(true));
    }
  }

  resetAllFilters(onlyRefresh = false) {
    return new Promise((resolve) => {
      const sortByLabel = R.sortBy(R.compose(R.toLower, R.prop('tlabel')));
      const sortByDefinition = R.sortBy(
        R.compose(R.toLower, R.prop('definition')),
      );
      const sortByName = R.sortBy(R.compose(R.toLower, R.prop('name')));
      const allStixCoreObjectsTypes = R.pipe(
        R.map((n) => n.entity_type),
        R.uniq,
        R.map((n) => ({
          label: n,
          tlabel: this.props.t(
            `${n.relationship_type ? 'relationship_' : 'entity_'}${
              n.entity_type
            }`,
          ),
        })),
        sortByLabel,
        R.map((n) => n.label),
      )(this.graphData.nodes);
      const allMarkedBy = R.pipe(
        R.map((n) => n.markedBy),
        R.flatten,
        R.uniqBy(R.prop('id')),
        sortByDefinition,
      )(R.union(this.graphData.nodes, this.graphData.links));
      const allCreatedBy = R.pipe(
        R.map((n) => n.createdBy),
        R.uniqBy(R.prop('id')),
        sortByName,
      )(R.union(this.graphData.nodes, this.graphData.links));
      if (onlyRefresh) {
        this.setState(
          {
            allStixCoreObjectsTypes,
            allMarkedBy,
            allCreatedBy,
          },
          () => {
            this.saveParameters(false);
            resolve(true);
          },
        );
      } else {
        this.setState(
          {
            allStixCoreObjectsTypes,
            allMarkedBy,
            allCreatedBy,
            stixCoreObjectsTypes: [],
            markedBy: [],
            createdBy: [],
            keyword: '',
          },
          () => {
            this.saveParameters(true);
            resolve(true);
          },
        );
      }
    });
  }

  handleZoomToFit(adjust = false) {
    let px = 50;
    if (this.graphData.nodes.length === 1) {
      px = 300;
    } else if (this.graphData.nodes.length < 4) {
      px = 200;
    } else if (this.graphData.nodes.length < 8) {
      px = 100;
    }
    if (adjust) {
      const container = document.getElementById('container');
      const { offsetWidth, offsetHeight } = container;
      this.setState({ width: offsetWidth, height: offsetHeight }, () => {
        this.graph.current.zoomToFit(400, px);
      });
    } else {
      this.graph.current.zoomToFit(400, px);
    }
  }

  onZoom() {
    this.zoomed += 1;
  }

  handleZoomEnd(zoom) {
    if (
      this.initialized
      && (zoom.k !== this.zoom?.k
        || zoom.x !== this.zoom?.x
        || zoom.y !== this.zoom?.y)
    ) {
      this.zoom = zoom;
      PARAMETERS$.next({ action: 'SaveParameters' });
    }
  }

  // eslint-disable-next-line class-methods-use-this
  handleDragEnd() {
    POSITIONS$.next({ action: 'SavePositions' });
  }

  handleNodeClick(node, event) {
    const { prevClick } = this.state;
    const now = new Date();
    if (event.ctrlKey || event.shiftKey || event.altKey) {
      if (this.selectedNodes.has(node)) {
        this.selectedNodes.delete(node);
      } else {
        this.selectedNodes.add(node);
      }
    } else {
      if (
        prevClick
        && prevClick.node === node
        && now - prevClick.time < DBL_CLICK_TIMEOUT
      ) {
        this.selectedNodes.clear();
        this.selectedLinks.clear();
        this.selectedNodes.add(node);
        this.setState({
          prevClick: null,
          numberOfSelectedNodes: this.selectedNodes.size,
        });
        return this.handleOpenExpandElements();
      }
      const untoggle = this.selectedNodes.has(node) && this.selectedNodes.size === 1;
      this.selectedNodes.clear();
      this.selectedLinks.clear();
      if (!untoggle) this.selectedNodes.add(node);
    }
    return this.setState({
      prevClick: {
        node,
        time: now,
      },
      numberOfSelectedNodes: this.selectedNodes.size,
      numberOfSelectedLinks: this.selectedLinks.size,
    });
  }

  handleLinkClick(link, event) {
    if (event.ctrlKey || event.shiftKey || event.altKey) {
      if (this.selectedLinks.has(link)) {
        this.selectedLinks.delete(link);
      } else {
        this.selectedLinks.add(link);
      }
    } else {
      const untoggle = this.selectedLinks.has(link) && this.selectedLinks.size === 1;
      this.selectedNodes.clear();
      this.selectedLinks.clear();
      if (!untoggle) {
        this.selectedLinks.add(link);
      }
    }
    this.setState({
      numberOfSelectedNodes: this.selectedNodes.size,
      numberOfSelectedLinks: this.selectedLinks.size,
    });
  }

  handleBackgroundClick() {
    this.selectedNodes.clear();
    this.selectedLinks.clear();
    this.setState({
      numberOfSelectedNodes: this.selectedNodes.size,
      numberOfSelectedLinks: this.selectedLinks.size,
    });
  }

  async handleAddEntity(stixCoreObject) {
    if (R.map((n) => n.id, this.graphObjects).includes(stixCoreObject.id)) return;
    this.graphObjects = [...this.graphObjects, stixCoreObject];
    this.graphData = buildGraphData(
      this.graphObjects,
      decodeGraphData(this.props.workspace.graph_data),
      this.props.t,
    );
    await this.resetAllFilters();
    const selectedTimeRangeInterval = computeTimeRangeInterval(
      this.graphObjects,
    );
    this.setState(
      {
        selectedTimeRangeInterval,
        graphData: applyFilters(
          this.graphData,
          this.state.stixCoreObjectsTypes,
          this.state.markedBy,
          this.state.createdBy,
          [],
          selectedTimeRangeInterval,
        ),
      },
      () => {
        setTimeout(() => this.handleZoomToFit(), 1500);
      },
    );
  }

  async handleAddRelation(stixCoreRelationship) {
    if (R.map((n) => n.id, this.graphObjects).includes(stixCoreRelationship.id)) return;
    this.graphObjects = [...this.graphObjects, stixCoreRelationship];
    this.graphData = buildGraphData(
      this.graphObjects,
      decodeGraphData(this.props.workspace.graph_data),
      this.props.t,
    );
    await this.resetAllFilters();
    const selectedTimeRangeInterval = computeTimeRangeInterval(
      this.graphObjects,
    );
    this.setState(
      {
        selectedTimeRangeInterval,
        graphData: applyFilters(
          this.graphData,
          this.state.stixCoreObjectsTypes,
          this.state.markedBy,
          this.state.createdBy,
          [],
          selectedTimeRangeInterval,
        ),
      },
      () => {
        commitMutation({
          mutation: investigationGraphRelationsAddMutation,
          variables: {
            id: this.props.workspace.id,
            input: {
              key: 'investigated_entities_ids',
              operation: 'add',
              value: [stixCoreRelationship.id],
            },
          },
        });
        setTimeout(() => this.handleZoomToFit(), 1500);
      },
    );
  }

  handleDelete(stixCoreObject) {
    const relationshipsToRemove = R.filter(
      (n) => n.from?.id === stixCoreObject.id || n.to?.id === stixCoreObject.id,
      this.graphObjects,
    );
    this.graphObjects = R.filter(
      (n) => n.id !== stixCoreObject.id
        && n.from?.id !== stixCoreObject.id
        && n.to?.id !== stixCoreObject.id,
      this.graphObjects,
    );
    this.graphData = buildGraphData(
      this.graphObjects,
      decodeGraphData(this.props.workspace.graph_data),
      this.props.t,
    );
    const toIds = R.map((n) => n.id, relationshipsToRemove);
    commitMutation({
      mutation: investigationAddStixCoreObjectsLinesRelationsDeleteMutation,
      variables: {
        id: this.props.workspace.id,
        input: {
          key: 'investigated_entities_ids',
          value: toIds,
          operation: 'remove',
        },
      },
    });
    this.setState({
      graphData: applyFilters(
        this.graphData,
        this.state.stixCoreObjectsTypes,
        this.state.markedBy,
        this.state.createdBy,
        [],
        this.state.selectedTimeRangeInterval,
      ),
    });
  }

  async handleDeleteSelected() {
    let idsToRemove = [];
    // Retrieve selected links
    const selectedLinks = Array.from(this.selectedLinks);
    const selectedLinksIds = R.filter(
      (n) => n !== undefined,
      R.map((n) => n.id, selectedLinks),
    );
    this.graphObjects = R.filter(
      (n) => !R.includes(n.id, selectedLinksIds),
      this.graphObjects,
    );
    idsToRemove = [...idsToRemove, ...selectedLinksIds];

    // Retrieve selected nodes
    const selectedNodes = Array.from(this.selectedNodes);
    const selectedNodesIds = R.filter(
      (n) => n !== undefined,
      R.map((n) => n.id, selectedNodes),
    );
    idsToRemove = [...idsToRemove, ...selectedNodesIds];

    // Retrieve links of selected nodes
    const relationshipsToRemove = R.filter(
      (n) => R.includes(n.from?.id, selectedNodesIds)
        || R.includes(n.to?.id, selectedNodesIds),
      this.graphObjects,
    );
    const relationshipsToIds = R.filter(
      (n) => n !== undefined,
      R.map((n) => n.id, relationshipsToRemove),
    );
    this.graphObjects = R.filter(
      (n) => !R.includes(n.id, selectedNodesIds)
        && !R.includes(n.from?.id, selectedNodesIds)
        && !R.includes(n.to?.id, selectedNodesIds),
      this.graphObjects,
    );
    idsToRemove = [...idsToRemove, ...relationshipsToIds];

    commitMutation({
      mutation: investigationAddStixCoreObjectsLinesRelationsDeleteMutation,
      variables: {
        id: this.props.workspace.id,
        input: {
          key: 'investigated_entities_ids',
          value: idsToRemove,
          operation: 'remove',
        },
      },
    });

    this.selectedLinks.clear();
    this.selectedNodes.clear();

    this.graphData = buildGraphData(
      this.graphObjects,
      decodeGraphData(this.props.workspace.graph_data),
      this.props.t,
    );
    await this.resetAllFilters();
    this.setState({
      graphData: applyFilters(
        this.graphData,
        this.state.stixCoreObjectsTypes,
        this.state.markedBy,
        this.state.createdBy,
        [],
        this.state.selectedTimeRangeInterval,
      ),
      numberOfSelectedNodes: this.selectedNodes.size,
      numberOfSelectedLinks: this.selectedLinks.size,
    });
  }

  handleCloseEntityEdition(entityId) {
    setTimeout(() => {
      fetchQuery(investigationGraphStixCoreObjectQuery, {
        id: entityId,
      })
        .toPromise()
        .then((data) => {
          const { stixCoreObject } = data;
          this.graphObjects = R.map(
            (n) => (n.id === stixCoreObject.id ? stixCoreObject : n),
            this.graphObjects,
          );
          this.graphData = buildGraphData(
            this.graphObjects,
            decodeGraphData(this.props.workspace.graph_data),
            this.props.t,
          );
          this.setState({
            graphData: applyFilters(
              this.graphData,
              this.state.stixCoreObjectsTypes,
              this.state.markedBy,
              this.state.createdBy,
              [],
              this.state.selectedTimeRangeInterval,
            ),
          });
        });
    }, 1500);
  }

  handleCloseRelationEdition(relationId) {
    setTimeout(() => {
      fetchQuery(investigationGraphStixCoreRelationshipQuery, {
        id: relationId,
      })
        .toPromise()
        .then((data) => {
          const { stixCoreRelationship } = data;
          this.graphObjects = R.map(
            (n) => (n.id === stixCoreRelationship.id ? stixCoreRelationship : n),
            this.graphObjects,
          );
          this.graphData = buildGraphData(
            this.graphObjects,
            decodeGraphData(this.props.workspace.graph_data),
            this.props.t,
          );
          this.setState({
            graphData: applyFilters(
              this.graphData,
              this.state.stixCoreObjectsTypes,
              this.state.markedBy,
              this.state.createdBy,
              [],
              this.state.selectedTimeRangeInterval,
            ),
          });
        });
    }, 1500);
  }

  handleCloseSightingEdition(relationId) {
    setTimeout(() => {
      fetchQuery(investigationGraphStixSightingRelationshipQuery, {
        id: relationId,
      })
        .toPromise()
        .then((data) => {
          const { stixSightingRelationship } = data;
          this.graphObjects = R.map(
            (n) => (n.id === stixSightingRelationship.id
              ? stixSightingRelationship
              : n),
            this.graphObjects,
          );
          this.graphData = buildGraphData(
            this.graphObjects,
            decodeGraphData(this.props.workspace.graph_data),
            this.props.t,
          );
          this.setState({
            graphData: applyFilters(
              this.graphData,
              this.state.stixCoreObjectsTypes,
              this.state.markedBy,
              this.state.createdBy,
              [],
              this.state.selectedTimeRangeInterval,
            ),
          });
        });
    }, 1500);
  }

  inSelectionRect(n) {
    const graphOrigin = this.graph.current.screen2GraphCoords(
      this.state.rectSelected.origin[0],
      this.state.rectSelected.origin[1],
    );
    const graphTarget = this.graph.current.screen2GraphCoords(
      this.state.rectSelected.target[0],
      this.state.rectSelected.target[1],
    );
    return (
      n.x >= graphOrigin.x
      && n.x <= graphTarget.x
      && n.y >= graphOrigin.y
      && n.y <= graphTarget.y
    );
  }

  handleRectSelectMove(e, coords) {
    if (this.state.selectRectangleModeFree) {
      const { left, top } = this.canvas.getBoundingClientRect();
      this.setState({
        rectSelected: {
          origin: [R.min(coords.origin[0], coords.target[0]) - left, R.min(coords.origin[1], coords.target[1]) - top],
          target: [R.max(coords.origin[0], coords.target[0]) - left, R.max(coords.origin[1], coords.target[1]) - top],
          shiftKey: e.shiftKey,
          altKey: e.altKey,
        },
      });
    }
  }

  handleRectSelectUp() {
    if (
      this.state.selectRectangleModeFree
      && (this.state.rectSelected.origin[0]
        !== this.state.rectSelected.target[0]
        || this.state.rectSelected.origin[1] !== this.state.rectSelected.target[1])
    ) {
      if (
        !this.state.rectSelected.shiftKey
        && !this.state.rectSelected.altKey
      ) {
        this.selectedLinks.clear();
        this.selectedNodes.clear();
      }
      if (this.state.rectSelected.altKey) {
        R.map(
          (n) => this.inSelectionRect(n) && this.selectedNodes.delete(n),
          this.state.graphData.nodes,
        );
      } else {
        R.map(
          (n) => this.inSelectionRect(n) && this.selectedNodes.add(n),
          this.state.graphData.nodes,
        );
      }
      this.setState({ numberOfSelectedNodes: this.selectedNodes.size });
    }
    this.setState({
      rectSelected: {
        origin: [0, 0],
        target: [0, 0],
        shiftKey: false,
        altKey: false,
      },
    });
  }

  handleSelectAll() {
    this.selectedLinks.clear();
    this.selectedNodes.clear();
    R.map((n) => this.selectedNodes.add(n), this.state.graphData.nodes);
    this.setState({ numberOfSelectedNodes: this.selectedNodes.size });
  }

  handleSelectByType(type) {
    this.selectedLinks.clear();
    this.selectedNodes.clear();
    R.map(
      (n) => n.entity_type === type && this.selectedNodes.add(n),
      this.state.graphData.nodes,
    );
    this.setState({ numberOfSelectedNodes: this.selectedNodes.size });
  }

  // eslint-disable-next-line class-methods-use-this
  async handleExpandElements(filters) {
    // Do not expand if nothing has been checked.
    if (
      (!filters.relationship_types
        || filters.relationship_types.length === 0)
      && (!filters.entity_types || filters.entity_types.length === 0)
    ) {
      return;
    }

    setStackDataInSessionStorage(
      investigationPreExpansionStateListStorageKey,
      {
        dateTime: new Date().getTime(),
        investigatedEntitiesList: this.graphObjects,
      },
      10,
    );

    this.handleToggleDisplayProgress();
    const selectedEntities = [...this.selectedLinks, ...this.selectedNodes];
    const selectedEntitiesIds = R.map((n) => n.id, selectedEntities);
    let newElementsIds = [];
    for (const n of selectedEntitiesIds) {
      // eslint-disable-next-line no-await-in-loop
      const newElements = await fetchQuery(
        investigationGraphStixRelationshipsQuery,
        {
          filters: {
            mode: 'or',
            filterGroups: [
              {
                mode: 'and',
                filterGroups: [],
                filters: [
                  { key: 'fromId', values: [n] },
                  { key: 'toTypes', values: filters.entity_types.map((o) => o.value) },
                  { key: 'relationship_type', values: filters.relationship_types.map((o) => o.value) },
                ],
              },
              {
                mode: 'and',
                filterGroups: [],
                filters: [
                  { key: 'toId', values: [n] },
                  { key: 'fromTypes', values: filters.entity_types.map((o) => o.value) },
                  { key: 'relationship_type', values: filters.relationship_types.map((o) => o.value) },
                ],
              },
            ],
            filters: [],
          },
        },
      )
        .toPromise()
        .then((data) => {
          const currentElementsIds = R.map((k) => k.id, this.graphObjects);
          const newNodes = R.pipe(
            R.map((k) => (k.node.from.id === n ? k.node.to : k.node.from)),
            R.filter((k) => !currentElementsIds.includes(k.id)),
          )(data.stixRelationships.edges);
          const newRelationships = R.pipe(
            R.map((k) => k.node),
            R.filter((k) => !currentElementsIds.includes(k.id)),
          )(data.stixRelationships.edges);
          return [...newNodes, ...newRelationships];
        });
      newElementsIds = [...R.map((k) => k.id, newElements), ...newElementsIds];
      this.graphObjects = [...newElements, ...this.graphObjects];
      this.fetchObjectRelCounts(newElements);
    }
    if (newElementsIds.length > 0) {
      this.graphData = buildGraphData(
        this.graphObjects,
        decodeGraphData(this.props.workspace.graph_data),
        this.props.t,
      );
      const selectedTimeRangeInterval = computeTimeRangeInterval(
        this.graphObjects,
      );
      if (filters.reset_filters) {
        await this.resetAllFilters();
      } else {
        await this.resetAllFilters(true);
      }
      this.setState(
        {
          selectedTimeRangeInterval,
          graphData: applyFilters(
            this.graphData,
            this.state.stixCoreObjectsTypes,
            this.state.markedBy,
            this.state.createdBy,
            [],
            selectedTimeRangeInterval,
          ),
        },
        () => {
          commitMutation({
            mutation: investigationGraphRelationsAddMutation,
            variables: {
              id: this.props.workspace.id,
              input: {
                key: 'investigated_entities_ids',
                operation: 'add',
                value: newElementsIds,
              },
            },
          });
          setTimeout(() => this.handleZoomToFit(), 1000);
        },
      );
    }
    this.handleToggleDisplayProgress();
  }

  handleRollBackToPreExpansionState() {
    const storedPreExpansion = getPreExpansionStateList();
    if (storedPreExpansion) {
      const currentStoredPreExpansion = JSON.parse(storedPreExpansion);
      const { investigatedEntitiesList } = currentStoredPreExpansion[0];

      const graphObjectsToRestore = this.graphObjects.filter((graphObject) => investigatedEntitiesList.find((investigatedEntity) => investigatedEntity.id === graphObject.id));
      const graphObjectsToAdd = investigatedEntitiesList.filter((investigatedEntities) => !this.graphObjects.find((graphObject) => graphObject.id === investigatedEntities.id));

      commitMutation({
        mutation: investigationAddStixCoreObjectsLinesRelationsDeleteMutation,
        variables: {
          id: this.props.workspace.id,
          input: {
            key: 'investigated_entities_ids',
            value: [
              ...graphObjectsToRestore.map((graphObjectToRestore) => graphObjectToRestore.id),
              ...graphObjectsToAdd.map((graphObjectToAdd) => graphObjectToAdd.id),
            ],
            operation: 'replace',
          },
        },
      });

      this.graphObjects = [...graphObjectsToRestore, ...graphObjectsToAdd];
      this.graphData = buildGraphData(
        [...graphObjectsToRestore, ...graphObjectsToAdd],
        decodeGraphData(this.props.workspace.graph_data),
        this.props.t,
      );

      this.setState({
        graphData: applyFilters(
          this.graphData,
          this.state.stixCoreObjectsTypes,
          this.state.markedBy,
          this.state.createdBy,
          [],
          this.state.selectedTimeRangeInterval,
        ),
      });

      updatePreExpansionStateList(currentStoredPreExpansion);
    }
  }

  handleOpenRollBackToPreExpansionStateDialog() {
    this.setState({ isRollBackPreExpandStateDialogOpen: true });
  }

  handleCloseRollBackToPreExpansionStateDialog() {
    this.setState({ isRollBackPreExpandStateDialogOpen: false });
  }

  handleResetLayout() {
    this.graphData = buildGraphData(this.graphObjects, {}, this.props.t);
    this.setState(
      {
        graphData: applyFilters(
          this.graphData,
          this.state.stixCoreObjectsTypes,
          this.state.markedBy,
          this.state.createdBy,
          [],
          this.state.selectedTimeRangeInterval,
        ),
      },
      () => {
        this.handleDragEnd();
        this.forceUpdate();
        this.graph.current.d3ReheatSimulation();
        POSITIONS$.next({ action: 'SavePositions' });
      },
    );
  }

  handleTimeRangeChange(interval) {
    this.setState({
      graphData: applyFilters(
        this.graphData,
        this.state.stixCoreObjectsTypes,
        this.state.markedBy,
        this.state.createdBy,
        [],
        interval,
      ),
      selectedTimeRangeInterval: interval,
    });
  }

  handleSearch(keyword) {
    this.selectedLinks.clear();
    this.selectedNodes.clear();
    if (isNotEmptyField(keyword)) {
      const filterByKeyword = (n) => keyword === ''
        || (getMainRepresentative(n) || '').toLowerCase().indexOf(keyword.toLowerCase())
          !== -1
        || (getSecondaryRepresentative(n) || '')
          .toLowerCase()
          .indexOf(keyword.toLowerCase()) !== -1
        || (n.entity_type || '').toLowerCase().indexOf(keyword.toLowerCase())
          !== -1;
      R.map(
        (n) => filterByKeyword(n) && this.selectedNodes.add(n),
        this.state.graphData.nodes,
      );
      this.setState({ numberOfSelectedNodes: this.selectedNodes.size });
    }
  }

  handleOpenExpandElements() {
    this.setState({ openExpandElements: true });
  }

  handleCloseExpandElements() {
    this.setState({ openExpandElements: false });
  }

  onResetExpandElements() {
    this.handleCloseExpandElements();
  }

  onSubmitExpandElements(values, { resetForm }) {
    this.handleExpandElements(values);
    resetForm();
  }

  render() {
    const { workspace, theme } = this.props;
    const {
      mode3D,
      modeFixed,
      modeTree,
      allStixCoreObjectsTypes,
      allMarkedBy,
      allCreatedBy,
      stixCoreObjectsTypes,
      selectRectangleModeFree,
      selectModeFree,
      selectModeFreeReady,
      markedBy,
      createdBy,
      graphData,
      numberOfSelectedNodes,
      numberOfSelectedLinks,
      displayProgress,
      displayTimeRange,
      selectedTimeRangeInterval,
      width,
      height,
      openExpandElements,
      navOpen,
      isRollBackPreExpandStateDialogOpen,
    } = this.state;
    const timeRangeInterval = computeTimeRangeInterval(this.graphObjects);
    const timeRangeValues = computeTimeRangeValues(
      timeRangeInterval,
      this.graphObjects,
    );
    const selectedEntities = [...this.selectedLinks, ...this.selectedNodes];

    return (
      <UserContext.Consumer>
        {({ bannerSettings }) => {
          const graphWidth = width || window.innerWidth - (navOpen ? 210 : 70);
          const graphHeight = height
            || window.innerHeight - 180 - bannerSettings.bannerHeightNumber * 2;
          return (
            <>
              <WorkspaceHeader
                workspace={workspace}
                adjust={this.handleZoomToFit.bind(this)}
                variant="investigation"
              />
              <Dialog
                PaperProps={{ elevation: 1 }}
                open={openExpandElements}
                onClose={this.handleCloseExpandElements.bind(this)}
                fullWidth={true}
                maxWidth="sm"
              >
                <InvestigationExpandForm
                  links={graphData.links}
                  selectedNodes={this.selectedNodes}
                  onSubmit={this.onSubmitExpandElements.bind(this)}
                  onReset={this.onResetExpandElements.bind(this)}
                />
              </Dialog>

              <InvestigationRollBackExpandDialog
                isOpen={isRollBackPreExpandStateDialogOpen}
                closeDialog={this.handleCloseRollBackToPreExpansionStateDialog.bind(this)}
                handleRollBackToPreExpansionState={this.handleRollBackToPreExpansionState.bind(this)}
              />

              <InvestigationGraphBar
                displayProgress={displayProgress}
                handleToggle3DMode={this.handleToggle3DMode.bind(this)}
                handleOpenRollBackToPreExpansionStateDialog={this.handleOpenRollBackToPreExpansionStateDialog.bind(this)}
                currentMode3D={mode3D}
                handleToggleTreeMode={this.handleToggleTreeMode.bind(this)}
                currentModeTree={modeTree}
                handleToggleFixedMode={this.handleToggleFixedMode.bind(this)}
                currentModeFixed={modeFixed}
                handleZoomToFit={this.handleZoomToFit.bind(this)}
                handleToggleCreatedBy={this.handleToggleCreateBy.bind(this)}
                handleToggleStixCoreObjectType={this.handleToggleStixCoreObjectType.bind(
                  this,
                )}
                handleToggleMarkedBy={this.handleToggleMarkedBy.bind(this)}
                handleToggleRectangleSelectModeFree={this.handleToggleRectangleSelectModeFree.bind(
                  this,
                )}
                handleToggleSelectModeFree={this.handleToggleSelectModeFree.bind(
                  this,
                )}
                stixCoreObjectsTypes={allStixCoreObjectsTypes}
                currentStixCoreObjectsTypes={stixCoreObjectsTypes}
                currentSelectRectangleModeFree={selectRectangleModeFree}
                currentSelectModeFree={selectModeFree}
                selectModeFreeReady={selectModeFreeReady}
                markedBy={allMarkedBy}
                currentMarkedBy={markedBy}
                createdBy={allCreatedBy}
                currentCreatedBy={createdBy}
                handleSelectAll={this.handleSelectAll.bind(this)}
                handleSelectByType={this.handleSelectByType.bind(this)}
                workspace={workspace}
                onAdd={this.handleAddEntity.bind(this)}
                onDelete={this.handleDelete.bind(this)}
                onAddRelation={this.handleAddRelation.bind(this)}
                handleOpenExpandElements={this.handleOpenExpandElements.bind(
                  this,
                )}
                handleCloseExpandElements={this.handleOpenExpandElements.bind(
                  this,
                )}
                handleDeleteSelected={this.handleDeleteSelected.bind(this)}
                selectedNodes={Array.from(this.selectedNodes)}
                selectedLinks={Array.from(this.selectedLinks)}
                numberOfSelectedNodes={numberOfSelectedNodes}
                numberOfSelectedLinks={numberOfSelectedLinks}
                handleCloseEntityEdition={this.handleCloseEntityEdition.bind(
                  this,
                )}
                handleCloseRelationEdition={this.handleCloseRelationEdition.bind(
                  this,
                )}
                handleCloseSightingEdition={this.handleCloseSightingEdition.bind(
                  this,
                )}
                handleResetLayout={this.handleResetLayout.bind(this)}
                displayTimeRange={displayTimeRange}
                handleToggleDisplayTimeRange={this.handleToggleDisplayTimeRange.bind(
                  this,
                )}
                timeRangeInterval={timeRangeInterval}
                selectedTimeRangeInterval={selectedTimeRangeInterval}
                handleTimeRangeChange={this.handleTimeRangeChange.bind(this)}
                timeRangeValues={timeRangeValues}
                handleSearch={this.handleSearch.bind(this)}
                navOpen={navOpen}
                resetAllFilters={this.resetAllFilters.bind(this, false)}
                openCreatedRelation={this.state.openCreatedRelation}
                handleCloseRelationCreation={() => this.setState({ openCreatedRelation: false })}
              />
              {selectedEntities.length > 0 && (
                <EntitiesDetailsRightsBar selectedEntities={selectedEntities} />
              )}
              {mode3D ? (
                <ForceGraph3D
                  ref={this.graph}
                  width={graphWidth}
                  height={graphHeight}
                  backgroundColor={theme.palette.background.default}
                  graphData={graphData}
                  nodeThreeObjectExtend={true}
                  nodeThreeObject={(node) => nodeThreePaint(node, theme.palette.text.primary)
                  }
                  linkColor={(link) => (this.selectedLinks.has(link)
                    ? theme.palette.secondary.main
                    : theme.palette.primary.main)
                  }
                  linkWidth={0.2}
                  linkDirectionalArrowLength={3}
                  linkDirectionalArrowRelPos={0.99}
                  linkThreeObjectExtend={true}
                  linkThreeObject={(link) => {
                    const sprite = new SpriteText(link.label);
                    sprite.color = 'lightgrey';
                    sprite.textHeight = 1.5;
                    return sprite;
                  }}
                  linkPositionUpdate={(sprite, { start, end }) => {
                    const middlePos = Object.assign(
                      ...['x', 'y', 'z'].map((c) => ({
                        [c]: start[c] + (end[c] - start[c]) / 2,
                      })),
                    );
                    Object.assign(sprite.position, middlePos);
                  }}
                  onNodeClick={this.handleNodeClick.bind(this)}
                  onNodeRightClick={(node) => {
                    // eslint-disable-next-line no-param-reassign
                    node.fx = undefined;
                    // eslint-disable-next-line no-param-reassign
                    node.fy = undefined;
                    // eslint-disable-next-line no-param-reassign
                    node.fz = undefined;
                    this.handleDragEnd();
                    this.forceUpdate();
                  }}
                  onNodeDrag={(node, translate) => {
                    if (this.selectedNodes.has(node)) {
                      [...this.selectedNodes]
                        .filter((selNode) => selNode !== node)
                        // eslint-disable-next-line no-shadow
                        .forEach((selNode) => ['x', 'y', 'z'].forEach(
                          // eslint-disable-next-line no-param-reassign,no-return-assign
                          (coord) => (selNode[`f${coord}`] = selNode[coord] + translate[coord]),
                        ));
                    }
                  }}
                  onNodeDragEnd={(node) => {
                    if (this.selectedNodes.has(node)) {
                      // finished moving a selected node
                      [...this.selectedNodes]
                        .filter((selNode) => selNode !== node) // don't touch node being dragged
                        // eslint-disable-next-line no-shadow
                        .forEach((selNode) => {
                          ['x', 'y'].forEach(
                            // eslint-disable-next-line no-param-reassign,no-return-assign
                            (coord) => (selNode[`f${coord}`] = undefined),
                          );
                          // eslint-disable-next-line no-param-reassign
                          selNode.fx = selNode.x;
                          // eslint-disable-next-line no-param-reassign
                          selNode.fy = selNode.y;
                          // eslint-disable-next-line no-param-reassign
                          selNode.fz = selNode.z;
                        });
                    }
                    // eslint-disable-next-line no-param-reassign
                    node.fx = node.x;
                    // eslint-disable-next-line no-param-reassign
                    node.fy = node.y;
                    // eslint-disable-next-line no-param-reassign
                    node.fz = node.z;
                  }}
                  onLinkClick={this.handleLinkClick.bind(this)}
                  onBackgroundClick={this.handleBackgroundClick.bind(this)}
                  cooldownTicks={modeFixed ? 0 : undefined}
                  dagMode={
                    // eslint-disable-next-line no-nested-ternary
                    modeTree === 'horizontal'
                      ? 'lr'
                      : modeTree === 'vertical'
                        ? 'td'
                        : undefined
                  }
                />
              ) : (
                <>
                  <LassoSelection
                    width={graphWidth}
                    height={graphHeight}
                    activated={selectModeFree && selectModeFreeReady}
                    graphDataNodes={graphData.nodes}
                    graph={this.graph}
                    setSelectedNodes={(nodes) => {
                      this.selectedNodes.clear();
                      Array.from(nodes).forEach((n) => this.selectedNodes.add(n));
                      this.setState({ numberOfSelectedNodes: nodes.size });
                    }}
                  />
                  <RelationSelection
                    activated={!(selectModeFree && selectModeFreeReady) && !selectRectangleModeFree}
                    width={graphWidth}
                    height={graphHeight}
                    graphDataNodes={graphData.nodes}
                    graph={this.graph}
                    setSelectedNodes={(nodes) => {
                      this.selectedNodes.clear();
                      Array.from(nodes).forEach((n) => this.selectedNodes.add(n));
                      this.setState({ numberOfSelectedNodes: this.selectedNodes.size, openCreatedRelation: true });
                    }}
                  />
                  <RectangleSelection
                    onSelect={(e, coords) => {
                      this.handleRectSelectMove(e, coords);
                    }}
                    onMouseUp={(e) => {
                      this.handleRectSelectUp(e);
                    }}
                    style={{
                      backgroundColor: hexToRGB(
                        theme.palette.background.accent,
                        0.3,
                      ),
                      borderColor: theme.palette.warning.main,
                    }}
                    disabled={!selectRectangleModeFree}
                  >
                    <ForceGraph2D
                      ref={this.graph}
                      width={graphWidth}
                      height={graphHeight}
                      graphData={graphData}
                      onZoom={this.onZoom.bind(this)}
                      onZoomEnd={this.handleZoomEnd.bind(this)}
                      nodeRelSize={4}
                      enablePanInteraction={
                        !selectRectangleModeFree && !selectModeFree
                      }
                      nodeCanvasObject={(
                        node,
                        ctx, //
                      ) =>
                        // eslint-disable-next-line implicit-arrow-linebreak
                        nodePaint(
                          {
                            selected: theme.palette.secondary.main,
                            inferred: theme.palette.warning.main,
                            numbersBackground: theme.palette.background.default,
                            numberText: theme.palette.text.secondary,
                            disabled: theme.palette.background.paper,
                          },
                          node,
                          node.color,
                          ctx,
                          this.selectedNodes.has(node),
                          false,
                          node.disabled,
                          true,
                        )
                      }
                      nodePointerAreaPaint={nodeAreaPaint}
                      // linkDirectionalParticles={(link) => (this.selectedLinks.has(link) ? 20 : 0)}
                      // linkDirectionalParticleWidth={1}
                      // linkDirectionalParticleSpeed={() => 0.004}
                      linkCanvasObjectMode={() => 'after'}
                      linkCanvasObject={(link, ctx) => linkPaint(link, ctx, theme.palette.text.primary)
                      }
                      linkColor={(link) => {
                        if (this.selectedLinks.has(link)) {
                          return theme.palette.secondary.main;
                        }
                        if (link.isNestedInferred) {
                          return theme.palette.warning.main;
                        }
                        if (link.disabled) {
                          return theme.palette.background.paper;
                        }
                        return theme.palette.primary.main;
                      }}
                      linkDirectionalArrowLength={3}
                      linkDirectionalArrowRelPos={0.99}
                      onNodeClick={this.handleNodeClick.bind(this)}
                      onNodeRightClick={(node) => {
                        // eslint-disable-next-line no-param-reassign
                        node.fx = undefined;
                        // eslint-disable-next-line no-param-reassign
                        node.fy = undefined;
                        this.handleDragEnd();
                        this.forceUpdate();
                      }}
                      onNodeDrag={(node, translate) => {
                        if (this.selectedNodes.has(node)) {
                          [...this.selectedNodes]
                            .filter((selNode) => selNode !== node)
                            // eslint-disable-next-line no-shadow
                            .forEach((selNode) => ['x', 'y'].forEach(
                              // eslint-disable-next-line no-param-reassign,no-return-assign
                              (coord) => (selNode[`f${coord}`] = selNode[coord] + translate[coord]),
                            ));
                        }
                      }}
                      onNodeDragEnd={(node) => {
                        if (this.selectedNodes.has(node)) {
                          // finished moving a selected node
                          [...this.selectedNodes]
                            .filter((selNode) => selNode !== node) // don't touch node being dragged
                            // eslint-disable-next-line no-shadow
                            .forEach((selNode) => {
                              ['x', 'y'].forEach(
                                // eslint-disable-next-line no-param-reassign,no-return-assign
                                (coord) => (selNode[`f${coord}`] = undefined),
                              );
                              // eslint-disable-next-line no-param-reassign
                              selNode.fx = selNode.x;
                              // eslint-disable-next-line no-param-reassign
                              selNode.fy = selNode.y;
                            });
                        }
                        // eslint-disable-next-line no-param-reassign
                        node.fx = node.x;
                        // eslint-disable-next-line no-param-reassign
                        node.fy = node.y;
                        this.handleDragEnd();
                      }}
                      onLinkClick={this.handleLinkClick.bind(this)}
                      onBackgroundClick={this.handleBackgroundClick.bind(this)}
                      cooldownTicks={modeFixed ? 0 : 100}
                      onEngineStop={() => this.setState({ selectModeFreeReady: true })
                      }
                      dagMode={
                        // eslint-disable-next-line no-nested-ternary
                        modeTree === 'horizontal'
                          ? 'lr'
                          : modeTree === 'vertical'
                            ? 'td'
                            : undefined
                      }
                    />
                  </RectangleSelection>
                </>
              )}
            </>
          );
        }}
      </UserContext.Consumer>
    );
  }
}

InvestigationGraphComponent.propTypes = {
  workspace: PropTypes.object,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

const InvestigationGraph = createFragmentContainer(
  InvestigationGraphComponent,
  {
    workspace: graphql`
      fragment InvestigationGraph_workspace on Workspace {
        id
        name
        description
        manifest
        graph_data
        tags
        type
        owner {
          id
          name
          entity_type
        }
        currentUserAccessRight
        ...WorkspaceManageAccessDialog_authorizedMembers
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
              ... on StixCyberObservable {
                observable_value
              }
              ... on StixFile {
                observableName: name
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
              ... on StixRelationship {
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
              }
              ... on StixRefRelationship {
                created_at
              }
              ... on StixCoreRelationship {
                relationship_type
                start_time
                stop_time
                confidence
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
            }
          }
        }
      }
    `,
  },
);

export default R.compose(inject18n, withRouter, withTheme)(InvestigationGraph);
