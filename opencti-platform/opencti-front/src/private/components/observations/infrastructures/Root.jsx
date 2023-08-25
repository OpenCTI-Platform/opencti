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
      ...WorkbenchFileViewer_entity
      ...PictureManagementViewer_entity
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
      ...WorkbenchFileViewer_entity
      ...PictureManagementViewer_entity
    }
    connectorsForImport {
      ...FileManager_connectorsImport
    }
    connectorsForExport {
      ...FileManager_connectorsExport
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
      match: {
        params: { infrastructureId },
      },
    } = this.props;
    return (
      <div>
        <TopBar />
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
                      path="/dashboard/observations/infrastructures/:infrastructureId/analyses"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            entityType={'Infrastructure'}
                            stixDomainObject={props.infrastructure}
                            PopoverComponent={<InfrastructurePopover />}
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
                      path="/dashboard/observations/infrastructures/:infrastructureId/files"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            stixDomainObject={props.infrastructure}
                            PopoverComponent={<InfrastructurePopover />}
                          />
                          <FileManager
                            {...routeProps}
                            id={infrastructureId}
                            connectorsImport={props.connectorsForImport}
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
};

export default withRouter(RootInfrastructure);
