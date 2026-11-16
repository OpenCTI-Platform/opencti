import React, { Suspense } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { Stack, Typography } from '@mui/material';
import IngestionDeduplicationRules from './IngestionDeduplicationRules';
import { UserEditionDeduplicationUsagesQuery } from './__generated__/UserEditionDeduplicationUsagesQuery.graphql';
import { useFormatter } from '../../../../../components/i18n';

const userEditionDeduplicationUsagesQuery = graphql`
  query UserEditionDeduplicationUsagesQuery($userId: ID!) {
    ingestionDeduplicationUserUsages(userId: $userId) {
      id
      name
      entity_type
    }
  }
`;

const UserIngestions = ({ userId }: { userId: string }) => {
  const { t_i18n } = useFormatter();
  const data = useLazyLoadQuery<UserEditionDeduplicationUsagesQuery>(
    userEditionDeduplicationUsagesQuery,
    { userId },
    { fetchPolicy: 'store-and-network' },
  );
  const usages = data.ingestionDeduplicationUserUsages;
  return (
    <Typography variant="body2" color="textSecondary" data-testid="user-deduplication-ingestions">
      {usages.length === 0
        ? t_i18n('No ingestion runs as this user: these rules apply as soon as one does.')
        : `${t_i18n('These rules apply to every ingestion running as this user:')} ${usages.map((usage) => usage.name).join(', ')}`}
    </Typography>
  );
};

interface UserEditionDeduplicationProps {
  userId: string;
}

const UserEditionDeduplication = ({ userId }: UserEditionDeduplicationProps) => (
  <Stack sx={{ gap: 2, paddingTop: 2 }}>
    <Suspense fallback={null}>
      <UserIngestions userId={userId} />
    </Suspense>
    <IngestionDeduplicationRules userId={userId} />
  </Stack>
);

export default UserEditionDeduplication;
