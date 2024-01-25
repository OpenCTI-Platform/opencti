import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link, Routes, Navigate, Route } from 'react-router-dom';
import { graphql } from 'react-relay';
import * as R from 'ramda';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import { QueryRenderer, requestSubscription } from '../../../../relay/environment';
import Report from './Report';
import ReportPopover from './ReportPopover';
import ReportKnowledge from './ReportKnowledge';
import ContainerHeader from '../../common/containers/ContainerHeader';
import Loader from '../../../../components/Loader';
import ContainerStixDomainObjects from '../../common/containers/ContainerStixDomainObjects';
import ContainerStixCyberObservables from '../../common/containers/ContainerStixCyberObservables';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import StixCoreObjectFilesAndHistory from '../../common/stix_core_objects/StixCoreObjectFilesAndHistory';
import StixDomainObjectContent from '../../common/stix_domain_objects/StixDomainObjectContent';
import inject18n from '../../../../components/i18n';
import withRouter from '../../../../utils/compat-router/withRouter';
import Breadcrumbs from '../../../../components/Breadcrumps';

const subscription = graphql`
  subscription RootReportSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on Report {
        ...Report_report
        ...ReportKnowledgeGraph_report
        ...ReportEditionContainer_report
        ...StixDomainObjectContent_stixDomainObject
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
  }
`;

const reportQuery = graphql`
  query RootReportQuery($id: String!) {
    report(id: $id) {
      id
      standard_id
      entity_type
      name
      ...Report_report
      ...ReportDetails_report
      ...ReportKnowledge_report
      ...ContainerHeader_container
      ...ContainerStixDomainObjects_container
      ...ContainerStixCyberObservables_container
      ...StixDomainObjectContent_stixDomainObject
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

class RootReport extends Component {
  constructor(props) {
    super(props);
    const {
      params: { reportId },
    } = props;
    this.sub = requestSubscription({
      subscription,
      variables: { id: reportId },
    });
  }

  componentWillUnmount() {
    this.sub.dispose();
  }

  render() {
    const {
      t,
      location,
      params: { reportId },
    } = this.props;
    return (
      <>
        <QueryRenderer
          query={reportQuery}
          variables={{ id: reportId }}
          render={({ props }) => {
            if (props) {
              if (props.report) {
                const { report } = props;
                let paddingRight = 0;
                if (
                  location.pathname.includes(
                    `/dashboard/analyses/reports/${report.id}/entities`,
                  )
                  || location.pathname.includes(
                    `/dashboard/analyses/reports/${report.id}/observables`,
                  )
                ) {
                  paddingRight = 250;
                }
                if (
                  location.pathname.includes(
                    `/dashboard/analyses/reports/${report.id}/content`,
                  )
                ) {
                  paddingRight = 350;
                }
                return (
                  <div style={{ paddingRight }} data-testid="report-details-page">
                    <Breadcrumbs variant="object" elements={[
                      { label: t('Analyses') },
                      { label: t('Reports'), link: '/dashboard/analyses/reports' },
                      { label: report.name, current: true },
                    ]}
                    />
                    <ContainerHeader
                      container={report}
                      PopoverComponent={<ReportPopover />}
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
                            `/dashboard/analyses/reports/${report.id}/knowledge`,
                          )
                            ? `/dashboard/analyses/reports/${report.id}/knowledge`
                            : location.pathname
                        }
                      >
                        <Tab
                          component={Link}
                          to={`/dashboard/analyses/reports/${report.id}`}
                          value={`/dashboard/analyses/reports/${report.id}`}
                          label={t('Overview')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/analyses/reports/${report.id}/knowledge`}
                          value={`/dashboard/analyses/reports/${report.id}/knowledge`}
                          label={t('Knowledge')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/analyses/reports/${report.id}/content`}
                          value={`/dashboard/analyses/reports/${report.id}/content`}
                          label={t('Content')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/analyses/reports/${report.id}/entities`}
                          value={`/dashboard/analyses/reports/${report.id}/entities`}
                          label={t('Entities')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/analyses/reports/${report.id}/observables`}
                          value={`/dashboard/analyses/reports/${report.id}/observables`}
                          label={t('Observables')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/analyses/reports/${report.id}/files`}
                          value={`/dashboard/analyses/reports/${report.id}/files`}
                          label={t('Data')}
                        />
                      </Tabs>
                    </Box>
                    <Routes>
                      <Route
                        path="/"
                        element={
                          <Report report={report} />
                        }
                      />
                      <Route
                        path="/entities"
                        element={
                          <ContainerStixDomainObjects
                            container={report}
                          />
                        }
                      />
                      <Route
                        path="/observables"
                        element={
                          <ContainerStixCyberObservables
                            container={report}
                          />
                        }
                      />
                      <Route
                        path="/knowledge"
                        element={<Navigate
                          to={`/dashboard/analyses/reports/${reportId}/knowledge/graph`}
                                 />}
                      />
                      <Route
                        path="/content"
                        element={
                          <StixDomainObjectContent
                            stixDomainObject={report}
                          />
                        }
                      />
                      <Route
                        path="/knowledge/*"
                        element={
                          <ReportKnowledge
                            report={report}
                          />
                        }
                      />
                      <Route
                        path="/files"
                        element={
                          <StixCoreObjectFilesAndHistory
                            id={reportId}
                            connectorsExport={props.connectorsForExport}
                            connectorsImport={props.connectorsForImport}
                            entity={report}
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

RootReport.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
};

export default R.compose(inject18n, withRouter)(RootReport);
