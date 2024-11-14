import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { propOr } from 'ramda';
import { createFragmentContainer, createRefetchContainer, graphql, useFragment } from 'react-relay';
import { Route, Routes } from 'react-router-dom';
import { containerAddStixCoreObjectsLinesRelationAddMutation } from '../../common/containers/ContainerAddStixCoreObjectsLines';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import ContainerHeader from '../../common/containers/ContainerHeader';
import GroupingKnowledgeGraph, { groupingKnowledgeGraphQuery } from './GroupingKnowledgeGraph';
import GroupingKnowledgeCorrelation, { groupingKnowledgeCorrelationQuery } from './GroupingKnowledgeCorrelation';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import GroupingPopover from './GroupingPopover';
import AttackPatternsMatrix from '../../techniques/attack_patterns/AttackPatternsMatrix';
import { buildViewParamsFromUrlAndStorage, saveViewParameters } from '../../../../utils/ListParameters';
import investigationAddFromContainer from '../../../../utils/InvestigationUtils';
import withRouter from '../../../../utils/compat_router/withRouter';

export const groupingKnowledgeAttackPatternsGraphQuery = graphql`
    query GroupingKnowledgeAttackPatternsGraphQuery($id: String!) {
        grouping(id: $id) {
            id
            name
            context
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
                id
                definition_type
                definition
                x_opencti_order
                x_opencti_color
            }
            ...GroupingKnowledgeAttackPatterns_fragment
        }
    }
`;

const GroupingAttackPatternsFragment = graphql`
    fragment GroupingKnowledgeAttackPatterns_fragment on Grouping {
        objects(all: true, types: ["Attack-Pattern"]) {
            edges {
                node {
                    ... on AttackPattern {
                        id
                        entity_type
                        parent_types
                        name
                        description
                        x_mitre_platforms
                        x_mitre_permissions_required
                        x_mitre_id
                        x_mitre_detection
                        isSubAttackPattern
                        parentAttackPatterns {
                            edges {
                                node {
                                    id
                                    name
                                    description
                                    x_mitre_id
                                }
                            }
                        }
                        subAttackPatterns {
                            edges {
                                node {
                                    id
                                    name
                                    description
                                    x_mitre_id
                                }
                            }
                        }
                        killChainPhases {
                            id
                            kill_chain_name
                            phase_name
                            x_opencti_order
                        }
                    }
                }
            }
        }
    }
`;

const AttackPatternMatrixComponent = (props) => {
  const {
    data,
    grouping,
    currentKillChain,
    currentModeOnlyActive,
    currentColorsReversed,
    handleChangeKillChain,
    handleToggleColorsReversed,
    handleToggleModeOnlyActive,
  } = props;
  const attackPatternObjects = useFragment(GroupingAttackPatternsFragment, data.grouping);
  const attackPatterns = (attackPatternObjects.objects.edges)
    .map((n) => n.node)
    .filter((n) => n.entity_type === 'Attack-Pattern');

  const handleAddEntity = (entity) => {
    const input = {
      toId: entity.id,
      relationship_type: 'object',
    };
    commitMutation({
      mutation: containerAddStixCoreObjectsLinesRelationAddMutation,
      variables: {
        id: grouping.id,
        input,
      },
      onCompleted: () => {
        props.relay.refetch({ id: grouping.id });
      },
    });
  };

  return (
    <AttackPatternsMatrix
      entity={grouping}
      attackPatterns={attackPatterns}
      currentKillChain={currentKillChain}
      currentModeOnlyActive={currentModeOnlyActive}
      currentColorsReversed={currentColorsReversed}
      handleChangeKillChain={handleChangeKillChain}
      handleToggleColorsReversed={handleToggleColorsReversed}
      handleToggleModeOnlyActive={handleToggleModeOnlyActive}
      handleAdd={handleAddEntity}
    />
  );
};

const AttackPatternMatrixContainer = createRefetchContainer(
  AttackPatternMatrixComponent,
  {
    data: GroupingAttackPatternsFragment,
  },
  groupingKnowledgeAttackPatternsGraphQuery,
);

class GroupingKnowledgeComponent extends Component {
  constructor(props) {
    const LOCAL_STORAGE_KEY = `grouping-knowledge-${props.grouping.id}`;
    super(props);
    const params = buildViewParamsFromUrlAndStorage(
      props.navigate,
      props.location,
      LOCAL_STORAGE_KEY,
    );
    this.state = {
      currentModeOnlyActive: propOr(false, 'currentModeOnlyActive', params),
      currentColorsReversed: propOr(false, 'currentColorsReversed', params),
      currentKillChain: propOr('mitre-attack', 'currentKillChain', params),
    };
  }

  saveView() {
    saveViewParameters(
      this.props.navigate,
      this.props.location,
      `grouping-knowledge-${this.props.grouping.id}`,
      this.state,
    );
  }

  handleToggleModeOnlyActive() {
    this.setState(
      { currentModeOnlyActive: !this.state.currentModeOnlyActive },
      () => this.saveView(),
    );
  }

  handleToggleColorsReversed() {
    this.setState(
      { currentColorsReversed: !this.state.currentColorsReversed },
      () => this.saveView(),
    );
  }

  handleChangeKillChain(event) {
    const { value } = event.target;
    this.setState({ currentKillChain: value }, () => this.saveView());
  }

  render() {
    const {
      grouping,
      location,
      params: { '*': mode },
      enableReferences,
    } = this.props;
    const { currentModeOnlyActive, currentColorsReversed, currentKillChain } = this.state;
    return (
      <div
        style={{
          width: '100%',
          height: '100%',
        }}
        id={location.pathname.includes('matrix') ? 'parent' : 'container'}
        data-testid='groupings-knowledge'
      >
        {mode !== 'graph' && (
          <ContainerHeader
            container={grouping}
            PopoverComponent={<GroupingPopover />}
            link={`/dashboard/analyses/groupings/${grouping.id}/knowledge`}
            modes={['graph', 'correlation', 'matrix']}
            currentMode={mode}
            knowledge={true}
            enableSuggestions={true}
            investigationAddFromContainer={investigationAddFromContainer}
          />
        )}
        <Routes>
          <Route
            path="/graph"
            element={
              <QueryRenderer
                query={groupingKnowledgeGraphQuery}
                variables={{ id: grouping.id }}
                render={({ props }) => {
                  if (props && props.grouping) {
                    return (
                      <GroupingKnowledgeGraph
                        grouping={props.grouping}
                        mode={mode}
                        enableReferences={enableReferences}
                      />
                    );
                  }
                  return (
                    <Loader
                      variant={LoaderVariant.inElement}
                      withTopMargin={true}
                    />
                  );
                }}
              />
                }
          />
          <Route
            path="/correlation"
            element={
              <QueryRenderer
                query={groupingKnowledgeCorrelationQuery}
                variables={{ id: grouping.id }}
                render={({ props }) => {
                  if (props && props.grouping) {
                    return (
                      <GroupingKnowledgeCorrelation grouping={props.grouping} />
                    );
                  }
                  return (
                    <Loader
                      variant={LoaderVariant.inElement}
                      withTopMargin={true}
                    />
                  );
                }}
              />
                }
          />
          <Route
            path="/matrix"
            element={
              <QueryRenderer
                query={groupingKnowledgeAttackPatternsGraphQuery}
                variables={{ id: grouping.id }}
                render={({ props }) => {
                  if (props && props.grouping) {
                    return (
                      <AttackPatternMatrixContainer
                        data={props}
                        grouping={grouping}
                        currentKillChain={currentKillChain}
                        currentModeOnlyActive={currentModeOnlyActive}
                        currentColorsReversed={currentColorsReversed}
                        handleChangeKillChain={this.handleChangeKillChain.bind(this)}
                        handleToggleColorsReversed={this.handleToggleColorsReversed.bind(this)}
                        handleToggleModeOnlyActive={this.handleToggleModeOnlyActive.bind(this)}
                      />
                    );
                  }
                  return (
                    <Loader
                      variant={LoaderVariant.inElement}
                      withTopMargin={true}
                    />
                  );
                }}
              />
                }
          />
          <Route
            path="/relations/:relationId"
            element={
              <StixCoreRelationship
                entityId={grouping.id}
              />
            }
          />
        </Routes>
      </div>
    );
  }
}

GroupingKnowledgeComponent.propTypes = {
  grouping: PropTypes.object,
  mode: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  navigate: PropTypes.func,
  enableReferences: PropTypes.bool,
};

const GroupingKnowledge = createFragmentContainer(GroupingKnowledgeComponent, {
  grouping: graphql`
    fragment GroupingKnowledge_grouping on Grouping {
      id
      editContext {
        name
        focusOn
      }
      ...ContainerHeader_container
    }
  `,
});

export default R.compose(withRouter)(GroupingKnowledge);
