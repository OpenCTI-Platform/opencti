/* eslint-disable @typescript-eslint/no-explicit-any */
// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { useMemo } from 'react';
import { Route, Redirect, useParams } from 'react-router-dom';
import { graphql, useSubscription } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import {
  QueryRenderer,
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
import { RootInfrastructureSubscription } from './__generated__/RootInfrastructureSubscription.graphql';
import { RootInfrastructureQuery$data } from './__generated__/RootInfrastructureQuery.graphql';

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

const RootInfrastructureComponent = () => {
  const { infrastructureId } = useParams() as { infrastructureId: string };
  const subConfig = useMemo<
  GraphQLSubscriptionConfig<RootInfrastructureSubscription>
  >(
    () => ({
      subscription,
      variables: { id: infrastructureId },
    }),
    [infrastructureId],
  );
  useSubscription(subConfig);
  return (
    <div>
      <TopBar />
      <QueryRenderer
        query={infrastructureQuery}
        variables={{ id: infrastructureId }}
        render={({ props }: { props: RootInfrastructureQuery$data }) => {
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
};

export default RootInfrastructureComponent;
