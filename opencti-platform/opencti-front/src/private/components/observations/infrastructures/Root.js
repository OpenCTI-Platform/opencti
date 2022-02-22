import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Redirect, withRouter } from 'react-router-dom';
import { graphql } from 'react-relay';
import {
  QueryRenderer,
  requestSubscription,
} from '../../../../relay/environment';
import TopBar from '../../nav/TopBar';
import Infrastructure from './Infrastructure';
import InfrastructureKnowledge from './InfrastructureKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import InfrastructurePopover from './InfrastructurePopover';
import Loader from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import StixDomainObjectIndicators from '../indicators/StixDomainObjectIndicators';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import ErrorNotFound from '../../../../components/ErrorNotFound';

const subscription = graphql`
  subscription RootInfrastructureSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on Infrastructure {
        ...Infrastructure_infrastructure
        ...InfrastructureEditionContainer_infrastructure
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...FilePendingViewer_entity
    }
  }
`;

const infrastructureQuery = graphql`
  query RootInfrastructureQuery($id: String!) {
    infrastructure(id: $id) {
      id
      standard_id
      name
      aliases
      x_opencti_graph_data
      ...Infrastructure_infrastructure
      ...InfrastructureKnowledge_infrastructure
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...FilePendingViewer_entity
    }
    connectorsForExport {
      ...FileManager_connectorsExport
    }
    settings {
      platform_enable_reference
    }
  }
`;

class RootInfrastructure extends Component {
  constructor(props) {
    super(props);
    const {
      match: {
        params: { infrastructureId },
      },
    } = props;
    this.sub = requestSubscription({
      subscription,
      variables: { id: infrastructureId },
    });
  }

  componentWillUnmount() {
    this.sub.dispose();
  }

  render() {
    const {
      me,
      match: {
        params: { infrastructureId },
      },
    } = this.props;
    return (
      <div>
        <TopBar me={me || null} />
        <QueryRenderer
          query={infrastructureQuery}
          variables={{ id: infrastructureId }}
          render={({ props }) => {
            if (props) {
              if (props.infrastructure) {
                return (
                  <div>
                    <Route
                      exact
                      path="/dashboard/observations/infrastructures/:infrastructureId"
                      render={(routeProps) => (
                        <Infrastructure
                          {...routeProps}
                          infrastructure={props.infrastructure}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/observations/infrastructures/:infrastructureId/knowledge"
                      render={() => (
                        <Redirect
                          to={`/dashboard/observations/infrastructures/${infrastructureId}/knowledge/overview`}
                        />
                      )}
                    />
                    <Route
                      path="/dashboard/observations/infrastructures/:infrastructureId/knowledge"
                      render={(routeProps) => (
                        <InfrastructureKnowledge
                          {...routeProps}
                          infrastructure={props.infrastructure}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/observations/infrastructures/:infrastructureId/analysis"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            stixDomainObject={props.infrastructure}
                            PopoverComponent={<InfrastructurePopover />}
                            enableReferences={props.settings.platform_enable_reference?.includes(
                              'Infrastructure',
                            )}
                          />
                          <StixCoreObjectOrStixCoreRelationshipContainers
                            {...routeProps}
                            stixDomainObjectOrStixCoreRelationship={
                              props.infrastructure
                            }
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/observations/infrastructures/:infrastructureId/indicators"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            stixDomainObject={props.infrastructure}
                            PopoverComponent={<InfrastructurePopover />}
                            enableReferences={props.settings.platform_enable_reference?.includes(
                              'Infrastructure',
                            )}
                          />
                          <StixDomainObjectIndicators
                            {...routeProps}
                            stixDomainObjectId={infrastructureId}
                            stixDomainObjectLink={`/dashboard/observations/infrastructures/${infrastructureId}/indicators`}
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/observations/infrastructures/:infrastructureId/indicators/relations/:relationId"
                      render={(routeProps) => (
                        <StixCoreRelationship
                          entityId={infrastructureId}
                          {...routeProps}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/observations/infrastructures/:infrastructureId/files"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            stixDomainObject={props.infrastructure}
                            PopoverComponent={<InfrastructurePopover />}
                            enableReferences={props.settings.platform_enable_reference?.includes(
                              'Infrastructure',
                            )}
                          />
                          <FileManager
                            {...routeProps}
                            id={infrastructureId}
                            connectorsImport={[]}
                            connectorsExport={props.connectorsForExport}
                            entity={props.infrastructure}
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/observations/infrastructures/:infrastructureId/history"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            stixDomainObject={props.infrastructure}
                            PopoverComponent={<InfrastructurePopover />}
                            enableReferences={props.settings.platform_enable_reference?.includes(
                              'Infrastructure',
                            )}
                          />
                          <StixCoreObjectHistory
                            {...routeProps}
                            stixCoreObjectId={infrastructureId}
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

RootInfrastructure.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
  me: PropTypes.object,
};

export default withRouter(RootInfrastructure);
