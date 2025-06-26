import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { propOr } from 'ramda';
import { createFragmentContainer, graphql } from 'react-relay';
import { Route, Routes } from 'react-router-dom';
import StixDomainObjectAttackPatterns from '../../common/stix_domain_objects/StixDomainObjectAttackPatterns';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import { QueryRenderer } from '../../../../relay/environment';
import ContainerHeader from '../../common/containers/ContainerHeader';
import GroupingKnowledgeGraph, { groupingKnowledgeGraphQuery } from './GroupingKnowledgeGraph';
import GroupingKnowledgeCorrelation, { groupingKnowledgeCorrelationQuery } from './GroupingKnowledgeCorrelation';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { buildViewParamsFromUrlAndStorage, saveViewParameters } from '../../../../utils/ListParameters';
import investigationAddFromContainer from '../../../../utils/InvestigationUtils';
import withRouter from '../../../../utils/compat_router/withRouter';

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

  render() {
    const {
      grouping,
      location,
      params: { '*': mode },
      enableReferences,
    } = this.props;

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
                        id={grouping.id}
                        data={props.grouping}
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
                      <GroupingKnowledgeCorrelation
                        data={props.grouping}
                        id={grouping.id}
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
            path="/matrix"
            element={
              <StixDomainObjectAttackPatterns
                stixDomainObjectId={grouping.id}
                entityType={grouping.entity_type}
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
      entity_type
      editContext {
        name
        focusOn
      }
      ...ContainerHeader_container
    }
  `,
});

export default R.compose(withRouter)(GroupingKnowledge);
