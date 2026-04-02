import { Suspense, useMemo, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery, useSubscription } from 'react-relay';
import { Route, useLocation, useParams } from 'react-router-dom';
import Security from 'src/utils/Security';
import StixCoreObjectContentRoot from '@components/common/stix_core_objects/StixCoreObjectContentRoot';
import FileManager from '@components/common/files/FileManager';
import StixCoreObjectHistory from '@components/common/stix_core_objects/StixCoreObjectHistory';
import SecurityCoverageKnowledge from '@components/analyses/security_coverages/SecurityCoverageKnowledge';
import StixCoreRelationship from '@components/common/stix_core_relationships/StixCoreRelationship';
import SecurityCoverage from './SecurityCoverage';
import { RootSecurityCoverageQuery } from './__generated__/RootSecurityCoverageQuery.graphql';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import StixDomainObjectMain from '@components/common/stix_domain_objects/StixDomainObjectMain';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { useFormatter } from '../../../../components/i18n';
import { KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import { getPaddingRight, isNotEmptyField } from '../../../../utils/utils';
import SecurityCoverageEdition from './SecurityCoverageEdition';
import SecurityCoverageDeletion from './SecurityCoverageDeletion';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Button from '@common/button/Button';
import { OaevLogo } from '../../../../static/images/logo_oaev';
import ExternalLinkPopover from '../../../../components/ExternalLinkPopover';
import { RootSecurityCoverageSubscription } from '@components/analyses/security_coverages/__generated__/RootSecurityCoverageSubscription.graphql';
import SecurityCoverageResult from '@components/analyses/security_coverages/SecurityCoverageResult';
import useHelper from '../../../../utils/hooks/useHelper';
import { PATH_SECURITY_COVERAGE, PATH_SECURITY_COVERAGES } from '@components/common/routes/paths';

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
  const { isFeatureEnable } = useHelper();
  const isOAEVResultFeatureEnabled = isFeatureEnable('OEAV_SECURITY_COVERAGE_RESULT_PAGE');

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
  const basePath = PATH_SECURITY_COVERAGE(securityCoverageId);
  const paddingRight = getPaddingRight(location.pathname, basePath, false);
  const isContent = location.pathname.includes('content');
  return (
    <>
      {securityCoverage ? (
        <div style={{ paddingRight }}>
          <Breadcrumbs elements={[
            { label: t_i18n('Analyses') },
            { label: t_i18n('Security coverages'), link: PATH_SECURITY_COVERAGES },
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
          <StixDomainObjectMain
            basePath={basePath}
            pages={{
              overview:
                <SecurityCoverage data={securityCoverage} />,
              ...(isOAEVResultFeatureEnabled ? { result: <SecurityCoverageResult id={securityCoverage.id} /> } : {}),
              content: (
                <StixCoreObjectContentRoot
                  stixCoreObject={securityCoverage}
                />
              ),
              files: (
                <FileManager
                  id={securityCoverageId}
                  connectorsImport={connectorsForImport}
                  connectorsExport={connectorsForExport}
                  entity={securityCoverage}
                />
              ),
              history: (
                <StixCoreObjectHistory
                  stixCoreObjectId={securityCoverageId}
                />
              ),
            }}
            extraActions={!isContent && (
              <>
                <Button
                  disabled={!hasExternalUri}
                  startIcon={<OaevLogo />}
                  onClick={() => setDisplayExternalLink(true)}
                  title={hasExternalUri ? securityCoverage.external_uri : undefined}
                  variant="tertiary"
                  size="small"
                  sx={{ mt: 2 }}
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
            extraRoutes={(
              <>
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
                {/** Is this route an error ? **/}
                <Route
                  path="/relations/:relationId"
                  element={(
                    <StixCoreRelationship
                      entityId={securityCoverageId}
                    />
                  )}
                />
              </>
            )}
          />
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
