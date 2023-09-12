import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Redirect, withRouter } from 'react-router-dom';
import { graphql } from 'react-relay';
import {
  QueryRenderer,
  requestSubscription,
} from '../../../../relay/environment';
import Grouping from './Grouping';
import GroupingPopover from './GroupingPopover';
import GroupingKnowledge from './GroupingKnowledge';
import ContainerHeader from '../../common/containers/ContainerHeader';
import Loader from '../../../../components/Loader';
import ContainerStixDomainObjects from '../../common/containers/ContainerStixDomainObjects';
import ContainerStixCyberObservables from '../../common/containers/ContainerStixCyberObservables';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import StixCoreObjectFilesAndHistory from '../../common/stix_core_objects/StixCoreObjectFilesAndHistory';

const subscription = graphql`
  subscription RootGroupingSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on Grouping {
        ...Grouping_grouping
        ...GroupingKnowledgeGraph_grouping
        ...GroupingEditionContainer_grouping
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
  }
`;

const groupingQuery = graphql`
  query RootGroupingQuery($id: String!) {
    grouping(id: $id) {
      standard_id
      ...Grouping_grouping
      ...GroupingDetails_grouping
      ...GroupingKnowledge_grouping
      ...ContainerHeader_container
      ...ContainerStixDomainObjects_container
      ...ContainerStixCyberObservables_container
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
    connectorsForExport {
      ...StixCoreObjectFilesAndHistory_connectorsExport
    }
    connectorsForImport {
      ...StixCoreObjectFilesAndHistory_connectorsImport
    }
  }
`;

class RootGrouping extends Component {
  constructor(props) {
    super(props);
    const {
      match: {
        params: { groupingId },
      },
    } = props;
    this.sub = requestSubscription({
      subscription,
      variables: { id: groupingId },
    });
  }

  componentWillUnmount() {
    this.sub.dispose();
  }

  render() {
    const {
      match: {
        params: { groupingId },
      },
    } = this.props;
    return (
      <div>
        <QueryRenderer
          query={groupingQuery}
          variables={{ id: groupingId }}
          render={({ props }) => {
            if (props) {
              if (props.grouping) {
                return (
                  <div>
                    <Route
                      exact
                      path="/dashboard/analyses/groupings/:groupingId"
                      render={(routeProps) => (
                        <Grouping {...routeProps} grouping={props.grouping} />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/analyses/groupings/:groupingId/entities"
                      render={(routeProps) => (
                        <React.Fragment>
                          <ContainerHeader
                            container={props.grouping}
                            PopoverComponent={<GroupingPopover />}
                            marginRight={260}
                          />
                          <ContainerStixDomainObjects
                            {...routeProps}
                            container={props.grouping}
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/analyses/groupings/:groupingId/observables"
                      render={(routeProps) => (
                        <React.Fragment>
                          <ContainerHeader
                            container={props.grouping}
                            PopoverComponent={<GroupingPopover />}
                            marginRight={260}
                          />
                          <ContainerStixCyberObservables
                            {...routeProps}
                            container={props.grouping}
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/analyses/groupings/:groupingId/knowledge"
                      render={() => (
                        <Redirect
                          to={`/dashboard/analyses/groupings/${groupingId}/knowledge/graph`}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/analyses/groupings/:groupingId/knowledge/:mode"
                      render={(routeProps) => (
                        <GroupingKnowledge
                          {...routeProps}
                          grouping={props.grouping}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/analyses/groupings/:groupingId/files"
                      render={(routeProps) => (
                        <React.Fragment>
                          <ContainerHeader
                            container={props.grouping}
                            PopoverComponent={<GroupingPopover />}
                            enableSuggestions={true}
                          />
                          <StixCoreObjectFilesAndHistory
                            {...routeProps}
                            id={groupingId}
                            connectorsExport={props.connectorsForExport}
                            connectorsImport={props.connectorsForImport}
                            entity={props.grouping}
                            withoutRelations={true}
                            bypassEntityId={true}
                          />
                        </React.Fragment>
                      )}
                    />
                  </div>
                );
              }
              return <ErrorNotFound />;
            }
            return <Loader />;
          }}
        />
      </div>
    );
  }
}

RootGrouping.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
};

export default withRouter(RootGrouping);
