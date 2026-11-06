import React, { Suspense } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { Stack } from '@mui/material';
import IngestionHealthBanner from '@components/data/connectors/IngestionHealthBanner';
import IngestionDeduplicationRules from '@components/integrations/deduplication/IngestionDeduplicationRules';
import { ConnectorDeduplicationUsagesQuery } from './__generated__/ConnectorDeduplicationUsagesQuery.graphql';
import { ConnectorDeduplicationUserRulesQuery } from './__generated__/ConnectorDeduplicationUserRulesQuery.graphql';
import Card from '../../../../components/common/card/Card';
import { useFormatter } from '../../../../components/i18n';
import useHelper from '../../../../utils/hooks/useHelper';
import useGranted, { INGESTION } from '../../../../utils/hooks/useGranted';

const connectorDeduplicationUsagesQuery = graphql`
  query ConnectorDeduplicationUsagesQuery($userId: ID!, $excludeConnectorId: ID) {
    ingestionDeduplicationUserUsages(userId: $userId, excludeConnectorId: $excludeConnectorId) {
      id
      name
      entity_type
    }
  }
`;

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

interface ConnectorDeduplicationProps {
  connectorId: string;
  connectorUserId: string;
}

const SharedUserWarning = ({ connectorId, connectorUserId }: ConnectorDeduplicationProps) => {
  const { t_i18n } = useFormatter();
  const data = useLazyLoadQuery<ConnectorDeduplicationUsagesQuery>(
    connectorDeduplicationUsagesQuery,
    { userId: connectorUserId, excludeConnectorId: connectorId },
    { fetchPolicy: 'store-and-network' },
  );
  const usages = data.ingestionDeduplicationUserUsages;
  if (usages.length === 0) {
    return null;
  }
  return (
    <IngestionHealthBanner
      severity="degraded"
      data-testid="connector-deduplication-shared-user"
      title={t_i18n('The user of this connector is also used by other ingestions: these rules apply to them too.')}
      lines={usages.map((usage) => `${usage.name} (${t_i18n(`entity_${usage.entity_type}`)})`)}
    />
  );
};

const ConnectorDeduplication = ({ connectorId, connectorUserId }: ConnectorDeduplicationProps) => {
  const { t_i18n } = useFormatter();
  return (
    <Card title={t_i18n('Deduplication')}>
      <Stack sx={{ gap: 2 }}>
        <Suspense fallback={null}>
          <SharedUserWarning connectorId={connectorId} connectorUserId={connectorUserId} />
        </Suspense>
        <IngestionDeduplicationRules userId={connectorUserId} />
      </Stack>
    </Card>
  );
};

export default ConnectorDeduplication;
