import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link, Switch, Redirect, Route, withRouter } from 'react-router-dom';
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
      match: {
        params: { reportId },
      },
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
      match: {
        params: { reportId },
      },
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
                  <div style={{ paddingRight }}>
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
                    <Switch>
                      <Route
                        exact
                        path="/dashboard/analyses/reports/:reportId"
                        render={(routeProps) => (
                          <Report {...routeProps} report={report} />
                        )}
                      />
                      <Route
                        exact
                        path="/dashboard/analyses/reports/:reportId/entities"
                        render={(routeProps) => (
                          <ContainerStixDomainObjects
                            {...routeProps}
                            container={report}
                          />
                        )}
                      />
                      <Route
                        exact
                        path="/dashboard/analyses/reports/:reportId/observables"
                        render={(routeProps) => (
                          <ContainerStixCyberObservables
                            {...routeProps}
                            container={report}
                          />
                        )}
                      />
                      <Route
                        exact
                        path="/dashboard/analyses/reports/:reportId/knowledge"
                        render={() => (
                          <Redirect
                            to={`/dashboard/analyses/reports/${reportId}/knowledge/graph`}
                          />
                        )}
                      />
                      <Route
                        exact
                        path="/dashboard/analyses/reports/:reportId/content"
                        render={(routeProps) => (
                          <StixDomainObjectContent
                            {...routeProps}
                            stixDomainObject={report}
                          />
                        )}
                      />
                      <Route
                        exact
                        path="/dashboard/analyses/reports/:reportId/knowledge/:mode"
                        render={(routeProps) => (
                          <ReportKnowledge
                            {...routeProps}
                            report={report}
                          />
                        )}
                      />
                      <Route
                        exact
                        path="/dashboard/analyses/reports/:reportId/files"
                        render={(routeProps) => (
                          <StixCoreObjectFilesAndHistory
                            {...routeProps}
                            id={reportId}
                            connectorsExport={props.connectorsForExport}
                            connectorsImport={props.connectorsForImport}
                            entity={report}
                            withoutRelations={true}
                            bypassEntityId={true}
                          />
                        )}
                      />
                    </Switch>
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
