import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link, Routes, Navigate, Route } from 'react-router-dom';
import { graphql } from 'react-relay';
import * as R from 'ramda';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import StixDomainObjectContent from '../../common/stix_domain_objects/StixDomainObjectContent';
import { QueryRenderer, requestSubscription } from '../../../../relay/environment';
import Grouping from './Grouping';
import GroupingPopover from './GroupingPopover';
import GroupingKnowledge from './GroupingKnowledge';
import ContainerHeader from '../../common/containers/ContainerHeader';
import Loader from '../../../../components/Loader';
import ContainerStixDomainObjects from '../../common/containers/ContainerStixDomainObjects';
import ContainerStixCyberObservables from '../../common/containers/ContainerStixCyberObservables';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import StixCoreObjectFilesAndHistory from '../../common/stix_core_objects/StixCoreObjectFilesAndHistory';
import inject18n from '../../../../components/i18n';
import withRouter from '../../../../utils/compat-router/withRouter';
import Breadcrumbs from '../../../../components/Breadcrumps';

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
      id
      standard_id
      entity_type
      name
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
      params: { groupingId },
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
      t,
      location,
      params: { groupingId },
    } = this.props;
    return (
      <>
        <QueryRenderer
          query={groupingQuery}
          variables={{ id: groupingId }}
          render={({ props }) => {
            if (props) {
              if (props.grouping) {
                const { grouping } = props;
                let paddingRight = 0;
                if (
                  location.pathname.includes(
                    `/dashboard/analyses/groupings/${grouping.id}/entities`,
                  )
                  || location.pathname.includes(
                    `/dashboard/analyses/groupings/${grouping.id}/observables`,
                  )
                ) {
                  paddingRight = 250;
                }
                if (
                  location.pathname.includes(
                    `/dashboard/analyses/groupings/${grouping.id}/content`,
                  )
                ) {
                  paddingRight = 350;
                }
                return (
                  <div style={{ paddingRight }}>
                    <Breadcrumbs variant="object" elements={[
                      { label: t('Analyses') },
                      { label: t('Groupings'), link: '/dashboard/analyses/groupings' },
                      { label: grouping.name, current: true },
                    ]}
                    />
                    <ContainerHeader
                      container={grouping}
                      PopoverComponent={<GroupingPopover />}
                      enableQuickSubscription={true}
                      enableQuickExport={true}
                      enableAskAi={true}
                    />
                    <Box
                      sx={{
                        borderBottom: 1,
                        borderColor: 'divider',
                        marginBottom: 4,
                      }}
                    >
                      <Tabs
                        value={
                          location.pathname.includes(
                            `/dashboard/analyses/groupings/${grouping.id}/knowledge`,
                          )
                            ? `/dashboard/analyses/groupings/${grouping.id}/knowledge`
                            : location.pathname
                        }
                      >
                        <Tab
                          component={Link}
                          to={`/dashboard/analyses/groupings/${grouping.id}`}
                          value={`/dashboard/analyses/groupings/${grouping.id}`}
                          label={t('Overview')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/analyses/groupings/${grouping.id}/knowledge`}
                          value={`/dashboard/analyses/groupings/${grouping.id}/knowledge`}
                          label={t('Knowledge')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/analyses/groupings/${grouping.id}/content`}
                          value={`/dashboard/analyses/groupings/${grouping.id}/content`}
                          label={t('Content')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/analyses/groupings/${grouping.id}/entities`}
                          value={`/dashboard/analyses/groupings/${grouping.id}/entities`}
                          label={t('Entities')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/analyses/groupings/${grouping.id}/observables`}
                          value={`/dashboard/analyses/groupings/${grouping.id}/observables`}
                          label={t('Observables')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/analyses/groupings/${grouping.id}/files`}
                          value={`/dashboard/analyses/groupings/${grouping.id}/files`}
                          label={t('Data')}
                        />
                      </Tabs>
                    </Box>
                    <Routes>
                      <Route
                        path="/"
                        element={
                          <Grouping grouping={grouping} />
                        }
                      />
                      <Route
                        path="/entities"
                        element={
                          <ContainerStixDomainObjects
                            container={grouping}
                          />
                        }
                      />
                      <Route
                        path="/observables"
                        element={
                          <ContainerStixCyberObservables
                            container={grouping}
                          />
                        }
                      />
                      <Route
                        path="/content"
                        element={
                          <StixDomainObjectContent
                            stixDomainObject={grouping}
                          />
                        }
                      />
                      <Route
                        path="/knowledge"
                        element={
                          <Navigate
                            to={`/dashboard/analyses/groupings/${groupingId}/knowledge/graph`}
                          />}
                      />
                      <Route
                        path="/knowledge/*"
                        element={
                          <GroupingKnowledge
                            grouping={grouping}
                          />
                        }
                      />
                      <Route
                        path="/files"
                        element={
                          <StixCoreObjectFilesAndHistory
                            id={groupingId}
                            connectorsExport={props.connectorsForExport}
                            connectorsImport={props.connectorsForImport}
                            entity={props.grouping}
                            withoutRelations={true}
                            bypassEntityId={true}
                          />
                        }
                      />
                    </Routes>
                  </div>
                );
              }
              return <ErrorNotFound />;
            }
            return <Loader />;
          }}
        />
      </>
    );
  }
}

RootGrouping.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
};

export default R.compose(inject18n, withRouter)(RootGrouping);
