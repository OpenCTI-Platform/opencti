import React from 'react';
import { Navigate, useLocation, useNavigate } from 'react-router-dom';
import { BuiltInIntegrationImport, ImportableBuiltInKind } from '@components/integrations/available/BuiltInIntegrationImport';
import Loader from '../../../components/Loader';

// Deep-link route segment -> built-in feed kind.
const KIND_BY_ROUTE_SEGMENT: [string, ImportableBuiltInKind][] = [
  ['deploy-csv-feed', 'csv'],
  ['deploy-taxii-feed', 'taxii'],
  ['deploy-rss-feed', 'rss'],
  ['deploy-sync', 'sync'],
];

// Landing page of the XTM Hub feed deploy deep links: downloads the shared
// configuration (handled by the import component through the route params)
// and opens the prefilled creation drawer over a loader. Closing the drawer
// lands on the deployed integrations view filtered on the feed kind.
const DeployBuiltInFeed = () => {
  const location = useLocation();
  const navigate = useNavigate();

  const kind = KIND_BY_ROUTE_SEGMENT.find(([segment]) => location.pathname.includes(segment))?.[1];
  if (!kind) {
    return <Navigate to="/dashboard/integrations/deployed" replace={true} />;
  }

  return (
    <>
      <Loader />
      <BuiltInIntegrationImport
        kind={kind}
        hideTrigger
        onClose={() => navigate(`/dashboard/integrations/deployed?kind=${kind}`, { replace: true })}
      />
    </>
  );
};

export default DeployBuiltInFeed;
