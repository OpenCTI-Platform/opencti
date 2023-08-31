/* eslint-disable @typescript-eslint/no-explicit-any */
// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { useMemo } from 'react';
import { Route, Redirect, useParams, Switch } from 'react-router-dom';
import { graphql, usePreloadedQuery, useSubscription } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import TopBar from '../../nav/TopBar';
import InfrastructureKnowledge from './InfrastructureKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import InfrastructurePopover from './InfrastructurePopover';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import { RootInfrastructureSubscription } from './__generated__/RootInfrastructureSubscription.graphql';
import { RootInfrastructureQuery } from './__generated__/RootInfrastructureQuery.graphql';
import Infrastructure from './Infrastructure';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';

const subscription = graphql`
  subscription RootInfrastructureSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on Infrastructure {
        ...Infrastructure_infrastructure
        ...InfrastructureEditionOverview_infrastructure
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
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
    }
    connectorsForImport {
      ...FileManager_connectorsImport
    }
    connectorsForExport {
      ...FileManager_connectorsExport
    }
  }
`;

const RootInfrastructureComponent = ({ queryRef, infrastructureId }) => {
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
  const data = usePreloadedQuery(infrastructureQuery, queryRef);
  const { infrastructure, connectorsForImport, connectorsForExport } = data;
  return (
    <>
      {infrastructure ? (
        <Switch>
          <Route
            exact
            path="/dashboard/observations/infrastructures/:infrastructureId"
            render={() => <Infrastructure data={infrastructure} />}
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
            render={() => (
              <InfrastructureKnowledge infrastructure={infrastructure} />
            )}
          />
          <Route
            exact
            path="/dashboard/observations/infrastructures/:infrastructureId/analyses"
            render={(routeProps) => (
              <React.Fragment>
                <StixDomainObjectHeader
                  entityType={'Infrastructure'}
                  stixDomainObject={infrastructure}
                  PopoverComponent={InfrastructurePopover}
                />
                <StixCoreObjectOrStixCoreRelationshipContainers
                  {...routeProps}
                  stixDomainObjectOrStixCoreRelationship={infrastructure}
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
                  stixDomainObject={infrastructure}
                  PopoverComponent={InfrastructurePopover}
                />
                <FileManager
                  {...routeProps}
                  id={infrastructureId}
                  connectorsImport={connectorsForImport}
                  connectorsExport={connectorsForExport}
                  entity={infrastructure}
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
                  entityType={'Infrastructure'}
                  disableSharing={true}
                  stixDomainObject={infrastructure}
                  PopoverComponent={InfrastructurePopover}
                />
                <StixCoreObjectHistory
                  {...routeProps}
                  stixCoreObjectId={infrastructureId}
                />
              </React.Fragment>
            )}
          />
        </Switch>
      ) : (
        <ErrorNotFound />
      )}
    </>
  );
};

const RootInfrastructure = () => {
  const { infrastructureId } = useParams() as { infrastructureId: string };
  const queryRef = useQueryLoading<RootInfrastructureQuery>(infrastructureQuery, { id: infrastructureId });
  return (
    <>
      <TopBar/>
      {queryRef && (
        <React.Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <RootInfrastructureComponent queryRef={queryRef} infrastructureId={infrastructureId} />
        </React.Suspense>
      )}
    </>
  );
};

export default RootInfrastructure;
