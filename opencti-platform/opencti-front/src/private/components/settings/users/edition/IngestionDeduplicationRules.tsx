import React, { Suspense, useState } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { Stack, Typography } from '@mui/material';
import { DeleteOutlined, EditOutlined } from '@mui/icons-material';
import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import IngestionDeduplicationRuleForm, { type IngestionDeduplicationRuleValue } from './IngestionDeduplicationRuleForm';
import { IngestionDeduplicationRulesQuery } from './__generated__/IngestionDeduplicationRulesQuery.graphql';
import DeleteDialog from '../../../../../components/DeleteDialog';
import ItemIcon from '../../../../../components/ItemIcon';
import Loader, { LoaderVariant } from '../../../../../components/Loader';
import Tag from '../../../../../components/common/tag/Tag';
import { useFormatter } from '../../../../../components/i18n';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import useDeletion from '../../../../../utils/hooks/useDeletion';
import useGranted, { INGESTION_SETINGESTIONS, SETTINGS_SETACCESSES } from '../../../../../utils/hooks/useGranted';

const ingestionDeduplicationRulesQuery = graphql`
  query IngestionDeduplicationRulesQuery($userId: ID!) {
    ingestionDeduplicationRules(userId: $userId) {
      id
      target_type
      excluded_fields
      ttl
    }
    ingestionDeduplicationAllowedTypes
    ingestionDeduplicationDefaultTtl
  }
`;

const ingestionDeduplicationRuleDeleteMutation = graphql`
  mutation IngestionDeduplicationRulesDeleteMutation($id: ID!) {
    ingestionDeduplicationRuleDelete(id: $id)
  }
`;

interface IngestionDeduplicationRulesProps {
  userId: string;
}

const IngestionDeduplicationRulesComponent = ({ userId }: IngestionDeduplicationRulesProps) => {
  const { t_i18n } = useFormatter();
  const canManage = useGranted([SETTINGS_SETACCESSES, INGESTION_SETINGESTIONS], true);
  const [fetchKey, setFetchKey] = useState(0);
  const [formOpen, setFormOpen] = useState(false);
  const [editedRule, setEditedRule] = useState<IngestionDeduplicationRuleValue | null>(null);
  const [deletedRuleId, setDeletedRuleId] = useState<string | null>(null);
  const data = useLazyLoadQuery<IngestionDeduplicationRulesQuery>(
    ingestionDeduplicationRulesQuery,
    { userId },
    { fetchKey, fetchPolicy: 'store-and-network' },
  );
  const refetch = () => setFetchKey((key) => key + 1);
  const [commitDelete] = useApiMutation(ingestionDeduplicationRuleDeleteMutation);
  const deletion = useDeletion({});
  const rules = data.ingestionDeduplicationRules;

  const submitDelete = () => {
    if (!deletedRuleId) return;
    deletion.setDeleting(true);
    commitDelete({
      variables: { id: deletedRuleId },
      onCompleted: () => {
        deletion.setDeleting(false);
        deletion.handleCloseDelete();
        setDeletedRuleId(null);
        refetch();
      },
      onError: () => deletion.setDeleting(false),
    });
  };

  return (
    <Stack sx={{ gap: 1 }}>
      {rules.length === 0 && (
        <Typography variant="body2" color="textSecondary">
          {t_i18n('No deduplication rule: every object is imported.')}
        </Typography>
      )}
      {rules.map((rule) => (
        <Stack key={rule.id} direction="row" sx={{ alignItems: 'center', gap: 1 }} data-testid="ingestion-deduplication-rule">
          <ItemIcon type={rule.target_type} />
          <Typography variant="body1" sx={{ minWidth: 160 }}>{t_i18n(`entity_${rule.target_type}`)}</Typography>
          <Stack direction="row" sx={{ gap: 0.5, flexWrap: 'wrap', flex: 1 }}>
            {rule.excluded_fields.map((field) => <Tag key={field} label={field} labelTextTransform="none" />)}
          </Stack>
          <Typography variant="body2" color="textSecondary" sx={{ whiteSpace: 'nowrap' }}>
            {rule.ttl
              ? `${t_i18n('Expires after')} ${rule.ttl} s`
              : `${t_i18n('Expires after')} ${data.ingestionDeduplicationDefaultTtl} s (${t_i18n('default')})`}
          </Typography>
          {canManage && (
            <>
              <IconButton
                aria-label={t_i18n('Update')}
                onClick={() => {
                  setEditedRule(rule);
                  setFormOpen(true);
                }}
              >
                <EditOutlined fontSize="small" />
              </IconButton>
              <IconButton
                aria-label={t_i18n('Delete')}
                onClick={() => {
                  setDeletedRuleId(rule.id);
                  deletion.handleOpenDelete();
                }}
              >
                <DeleteOutlined fontSize="small" />
              </IconButton>
            </>
          )}
        </Stack>
      ))}
      {canManage && !formOpen && (
        <div>
          <Button
            variant="secondary"
            onClick={() => {
              setEditedRule(null);
              setFormOpen(true);
            }}
          >
            {t_i18n('Add a deduplication rule')}
          </Button>
        </div>
      )}
      {formOpen && (
        <IngestionDeduplicationRuleForm
          key={editedRule?.id ?? 'new'}
          userId={userId}
          allowedTypes={data.ingestionDeduplicationAllowedTypes}
          defaultTtl={data.ingestionDeduplicationDefaultTtl}
          rule={editedRule}
          onClose={() => setFormOpen(false)}
          onCompleted={refetch}
        />
      )}
      <DeleteDialog
        deletion={deletion}
        submitDelete={submitDelete}
        message={t_i18n('Do you want to delete this deduplication rule?')}
      />
    </Stack>
  );
};

const IngestionDeduplicationRules = (props: IngestionDeduplicationRulesProps) => (
  <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
    <IngestionDeduplicationRulesComponent {...props} />
  </Suspense>
);

export default IngestionDeduplicationRules;
