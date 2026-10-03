import { Suspense, useState } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { VerifiedUserOutlined } from '@mui/icons-material';
import Button from '@common/button/Button';
import { useFormatter } from '../../../../components/i18n';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import { normalizeFilterGroupForBackend } from '../../../../utils/filters/filtersUtils';
import IocValidationRequestDialog from './IocValidationRequestDialog';
import { buildValidationCandidateFilters, IOC_VALIDATION_MAX_INDICATORS, selectValidationCandidates } from './disseminationAssuranceUtils';
import type { LiveDeploymentsValidationButtonQuery } from './__generated__/LiveDeploymentsValidationButtonQuery.graphql';

// Unproven and proven candidates are paginated separately so the request limit is filled with unproven ones first.
const liveDeploymentsQuery = graphql`
  query LiveDeploymentsValidationButtonQuery($unprovenFilters: FilterGroup, $provenFilters: FilterGroup, $count: Int!) {
    unproven: stixCoreRelationships(first: $count, orderBy: last_sync_at, orderMode: desc, filters: $unprovenFilters) {
      edges {
        node {
          id
          deployment_status
          validation_status
          from {
            ... on Indicator {
              id
            }
          }
          to {
            ... on SecurityPlatform {
              id
              name
            }
          }
        }
      }
    }
    proven: stixCoreRelationships(first: $count, orderBy: last_sync_at, orderMode: desc, filters: $provenFilters) {
      edges {
        node {
          id
          deployment_status
          validation_status
          from {
            ... on Indicator {
              id
            }
          }
          to {
            ... on SecurityPlatform {
              id
              name
            }
          }
        }
      }
    }
  }
`;

interface LiveDeploymentsValidationButtonProps {
  side: 'indicator' | 'platform';
  entityId: string;
}

const LiveDeploymentsDialog = ({ side, entityId, onClose }: LiveDeploymentsValidationButtonProps & { onClose: () => void }) => {
  const { t_i18n, n } = useFormatter();
  const { unproven, proven } = useLazyLoadQuery<LiveDeploymentsValidationButtonQuery>(
    liveDeploymentsQuery,
    {
      count: IOC_VALIDATION_MAX_INDICATORS,
      unprovenFilters: normalizeFilterGroupForBackend(buildValidationCandidateFilters(side, entityId, false)),
      provenFilters: normalizeFilterGroupForBackend(buildValidationCandidateFilters(side, entityId, true)),
    },
    { fetchPolicy: 'network-only' },
  );
  const nodes = [...(unproven?.edges ?? []), ...(proven?.edges ?? [])].map((edge) => edge?.node).filter((node) => !!node);
  const platforms = new Map<string, string>();
  nodes.forEach((node) => {
    if (node.to?.id) platforms.set(node.to.id, node.to.name ?? node.to.id);
  });
  const indicatorIds = side === 'indicator'
    ? [entityId]
    : selectValidationCandidates(nodes.map((node) => ({
        indicatorId: node.from?.id ?? '',
        platformId: entityId,
        deploymentStatus: node.deployment_status,
        validationStatus: node.validation_status,
      })).filter((candidate) => candidate.indicatorId), false);
  const platformOptions = [...platforms.entries()].map(([id, name]) => ({ id, name }));
  const summary = side === 'indicator'
    ? `${t_i18n('Live on')} ${n(platformOptions.length)} ${t_i18n('security platform(s)')}`
    : `${n(indicatorIds.length)} ${t_i18n('live indicator(s) selected, never validated first')}`;
  return (
    <IocValidationRequestDialog
      open
      onClose={onClose}
      indicatorIds={platformOptions.length > 0 ? indicatorIds : []}
      platforms={platformOptions}
      defaultName={`${t_i18n('Validation of')} ${n(platformOptions.length)} ${t_i18n('security platform(s)')}`}
      summary={platformOptions.length > 0 ? summary : t_i18n('No live deployment to validate')}
    />
  );
};

/** Opens the validation request dialog for the live deployments of an indicator or of a security platform. */
const LiveDeploymentsValidationButton = (props: LiveDeploymentsValidationButtonProps) => {
  const { t_i18n } = useFormatter();
  const [open, setOpen] = useState(false);
  return (
    <Security needs={[KNOWLEDGE_KNUPDATE]}>
      <>
        <Button
          variant="secondary"
          startIcon={<VerifiedUserOutlined fontSize="small" />}
          onClick={() => setOpen(true)}
          data-testid="request-validation-button"
        >
          {t_i18n('Request validation')}
        </Button>
        {open && (
          <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
            <LiveDeploymentsDialog {...props} onClose={() => setOpen(false)} />
          </Suspense>
        )}
      </>
    </Security>
  );
};

export default LiveDeploymentsValidationButton;
