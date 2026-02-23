import React, { Suspense, useMemo, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery, useSubscription } from 'react-relay';
import { Link, Route, Routes, useLocation, useParams } from 'react-router-dom';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import Security from 'src/utils/Security';
import StixCoreObjectContentRoot from '@components/common/stix_core_objects/StixCoreObjectContentRoot';
import FileManager from '@components/common/files/FileManager';
import StixCoreObjectHistory from '@components/common/stix_core_objects/StixCoreObjectHistory';
import SecurityCoverageKnowledge from '@components/analyses/security_coverages/SecurityCoverageKnowledge';
import StixCoreRelationship from '@components/common/stix_core_relationships/StixCoreRelationship';
import SecurityCoverage from './SecurityCoverage';
import { RootSecurityCoverageQuery } from './__generated__/RootSecurityCoverageQuery.graphql';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { useFormatter } from '../../../../components/i18n';
import { KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import { getCurrentTab, getPaddingRight, isNotEmptyField } from '../../../../utils/utils';
import SecurityCoverageEdition from './SecurityCoverageEdition';
import SecurityCoverageDeletion from './SecurityCoverageDeletion';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Button from '@common/button/Button';
import { OaevLogo } from '../../../../static/images/logo_oaev';
import ExternalLinkPopover from '../../../../components/ExternalLinkPopover';
import { RootSecurityCoverageSubscription } from '@components/analyses/security_coverages/__generated__/RootSecurityCoverageSubscription.graphql';

const subscription = graphql`
    subscription RootSecurityCoverageSubscription($id: ID!) {
        securityCoverage(id: $id) {
            id
            external_uri
            ...SecurityCoverage_securityCoverage
        }
    }
`;

const securityCoverageQuery = graphql`
  query RootSecurityCoverageQuery($id: String!) {
    securityCoverage(id: $id) {
      id
      external_uri
      standard_id
      entity_type
      name
      description
      objectMarking {
        id
      }
      currentUserAccessRight
      ...SecurityCoverage_securityCoverage
      ...SecurityCoverageKnowledge_securityCoverage
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
      ...StixCoreObjectContent_stixCoreObject
      ...StixCoreObjectSharingListFragment
    }
    connectorsForImport {
      ...FileManager_connectorsImport
    }
    connectorsForExport {
      ...FileManager_connectorsExport
    }
  }
`;

type RootSecurityCoverageProps = {
  securityCoverageId: string;
  queryRef: PreloadedQuery<RootSecurityCoverageQuery>;
};

const RootSecurityCoverage = ({ queryRef, securityCoverageId }: RootSecurityCoverageProps) => {
  const location = useLocation();
  const { t_i18n } = useFormatter();
  const {
    securityCoverage,
    connectorsForExport,
    connectorsForImport,
  } = usePreloadedQuery<RootSecurityCoverageQuery>(securityCoverageQuery, queryRef);

  const subConfig = useMemo(() => ({
    subscription,
    variables: { id: securityCoverageId },
  }), [securityCoverageId]);

  useSubscription<RootSecurityCoverageSubscription>(subConfig);

  const [displayExternalLink, setDisplayExternalLink] = useState(false);
  const hasExternalUri = isNotEmptyField(securityCoverage?.external_uri);
  const paddingRight = getPaddingRight(location.pathname, securityCoverageId, '/dashboard/analyses/security_coverages', false);
  const isContent = location.pathname.includes('content');
  return (
    <>
      {securityCoverage ? (
        <div style={{ paddingRight }}>
          <Breadcrumbs elements={[
            { label: t_i18n('Analyses') },
            { label: t_i18n('Security coverages'), link: '/dashboard/analyses/security_coverages' },
            { label: securityCoverage.name, current: true },
          ]}
          />
          <StixDomainObjectHeader
            entityType="Security-Coverage"
            stixDomainObject={securityCoverage}
            EditComponent={(
              <Security needs={[KNOWLEDGE_KNUPDATE]}>
                <SecurityCoverageEdition securityCoverageId={securityCoverage.id} />
              </Security>
            )}
            DeleteComponent={({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) => (
              <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
                <SecurityCoverageDeletion securityCoverageId={securityCoverage.id} isOpen={isOpen} handleClose={onClose} />
              </Security>
            )}
            enableEnricher={true}
            enableQuickSubscription={true}
            redirectToContent={true}
            noAliases={true}
            enableEnrollPlaybook={true}
          />
          <Box
            sx={{
              borderBottom: 1,
              borderColor: 'divider',
              marginBottom: 3,
              display: 'flex',
              justifyContent: 'space-between',
              alignItem: 'center',
            }}
          >
            <Tabs value={getCurrentTab(location.pathname, securityCoverage.id, '/dashboard/analyses/security_coverages')}>
              <Tab
                component={Link}
                to={`/dashboard/analyses/security_coverages/${securityCoverage.id}`}
                value={`/dashboard/analyses/security_coverages/${securityCoverage.id}`}
                label={t_i18n('Overview')}
              />
              <Tab
                component={Link}
                to={`/dashboard/analyses/security_coverages/${securityCoverage.id}/content`}
                value={`/dashboard/analyses/security_coverages/${securityCoverage.id}/content`}
                label={t_i18n('Content')}
              />
              <Tab
                component={Link}
                to={`/dashboard/analyses/security_coverages/${securityCoverage.id}/files`}
                value={`/dashboard/analyses/security_coverages/${securityCoverage.id}/files`}
                label={t_i18n('Data')}
              />
              <Tab
                component={Link}
                to={`/dashboard/analyses/security_coverages/${securityCoverage.id}/history`}
                value={`/dashboard/analyses/security_coverages/${securityCoverage.id}/history`}
                label={t_i18n('History')}
              />
            </Tabs>
            {!isContent && (
              <>
                <Button
                  disabled={!hasExternalUri}
                  startIcon={<OaevLogo />}
                  onClick={() => setDisplayExternalLink(true)}
                  title={hasExternalUri ? securityCoverage.external_uri : undefined}
                  variant="secondary"
                >
                  {hasExternalUri ? `${t_i18n('Go to OpenAEV')}` : `${t_i18n('Provisioning OpenAEV')}`}
                </Button>
                <ExternalLinkPopover
                  externalLink={hasExternalUri ? securityCoverage.external_uri : undefined}
                  displayExternalLink={displayExternalLink}
                  setDisplayExternalLink={setDisplayExternalLink}
                />
              </>
            )}
          </Box>
          <Routes>
            <Route
              path="/"
              element={
                <SecurityCoverage data={securityCoverage} />
              }
            />
            <Route
              path="/knowledge/*"
              element={(
                <div>
                  <SecurityCoverageKnowledge
                    securityCoverageData={securityCoverage}
                  />
                </div>
              )}
            />
            <Route
              path="/content/*"
              element={(
                <StixCoreObjectContentRoot
                  stixCoreObject={securityCoverage}
                />
              )}
            />
            <Route
              path="/files"
              element={(
                <FileManager
                  id={securityCoverageId}
                  connectorsImport={connectorsForImport}
                  connectorsExport={connectorsForExport}
                  entity={securityCoverage}
                />
              )}
            />
            <Route
              path="/history"
              element={(
                <StixCoreObjectHistory
                  stixCoreObjectId={securityCoverageId}
                />
              )}
            />
            <Route
              path="/relations/:relationId"
              element={(
                <StixCoreRelationship
                  entityId={securityCoverageId}
                />
              )}
            />
          </Routes>
        </div>
      ) : (
        <ErrorNotFound />
      )}
    </>
  );
};

const Root = () => {
  const { securityCoverageId } = useParams() as { securityCoverageId: string };
  const queryRef = useQueryLoading<RootSecurityCoverageQuery>(securityCoverageQuery, {
    id: securityCoverageId,
  });
  return (
    <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
      {queryRef && (
        <RootSecurityCoverage queryRef={queryRef} securityCoverageId={securityCoverageId} />
      )}
    </Suspense>
  );
};

export default Root;
