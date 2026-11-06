import React, { Suspense } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import IngestionHealthBanner from '@components/data/connectors/IngestionHealthBanner';
import { ConnectorDeduplicationUserRulesQuery } from './__generated__/ConnectorDeduplicationUserRulesQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import useHelper from '../../../../utils/hooks/useHelper';
import useGranted, { INGESTION } from '../../../../utils/hooks/useGranted';

const connectorDeduplicationUserRulesQuery = graphql`
  query ConnectorDeduplicationUserRulesQuery($userId: ID!) {
    ingestionDeduplicationRules(userId: $userId) {
      id
      target_type
    }
  }
`;

const UserChangeWarningComponent = ({ previousUserId }: { previousUserId: string }) => {
  const { t_i18n } = useFormatter();
  const data = useLazyLoadQuery<ConnectorDeduplicationUserRulesQuery>(
    connectorDeduplicationUserRulesQuery,
    { userId: previousUserId },
    { fetchPolicy: 'store-and-network' },
  );
  const rules = data.ingestionDeduplicationRules;
  if (rules.length === 0) {
    return null;
  }
  return (
    <IngestionHealthBanner
      severity="degraded"
      data-testid="connector-deduplication-user-change"
      title={t_i18n('The deduplication rules of the current user stay with that user and will not apply to the new one.')}
      lines={rules.map((rule) => t_i18n(`entity_${rule.target_type}`))}
    />
  );
};

// Shown while the user of a connector is being changed
export const ConnectorUserChangeDeduplicationWarning = ({ previousUserId, newUserId }: { previousUserId?: string | null; newUserId?: string | null }) => {
  const { isFeatureEnable } = useHelper();
  const userHasIngestionCapability = useGranted([INGESTION]);
  if (!isFeatureEnable('INGESTION_DEDUPLICATION') || !userHasIngestionCapability || !previousUserId || !newUserId || previousUserId === newUserId) {
    return null;
  }
  return (
    <Suspense fallback={null}>
      <UserChangeWarningComponent previousUserId={previousUserId} />
    </Suspense>
  );
};
