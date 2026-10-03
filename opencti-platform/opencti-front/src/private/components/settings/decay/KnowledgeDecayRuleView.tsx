import React, { useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import Grid from '@mui/material/Grid';
import Box from '@mui/material/Box';
import Alert from '@mui/material/Alert';
import { EditOutlined } from '@mui/icons-material';
import Button from '@common/button/Button';
import Card from '@common/card/Card';
import Drawer from '@components/common/drawer/Drawer';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import FilterIconButton from '../../../../components/FilterIconButton';
import { useFormatter } from '../../../../components/i18n';
import Label from '../../../../components/common/label/Label';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { handleErrorInForm } from '../../../../relay/environment';
import { FormikHelpers } from 'formik';
import { notifyPayloadErrors } from '../../common/provenance/provenanceUtils';
import KnowledgeDecayRuleForm, {
  KNOWLEDGE_FRESHNESS_POLICY_LABELS,
  type KnowledgeDecayRuleFormValues,
  type KnowledgeDecayRuleInput,
  type KnowledgeFreshnessPolicy,
} from './KnowledgeDecayRuleForm';
import { KnowledgeDecayRuleView_decayRule$key } from './__generated__/KnowledgeDecayRuleView_decayRule.graphql';
import { KnowledgeDecayRuleViewEditMutation } from './__generated__/KnowledgeDecayRuleViewEditMutation.graphql';

const knowledgeDecayRuleViewFragment = graphql`
  fragment KnowledgeDecayRuleView_decayRule on DecayRule {
    id
    name
    description
    built_in
    active
    order
    target_scope
    target_types
    freshness_policy
    stale_after_days
    freshness_confidence_step
    decay_filters
    staleElementsCount
  }
`;

const knowledgeDecayRuleViewEditMutation = graphql`
  mutation KnowledgeDecayRuleViewEditMutation($id: ID!, $input: [EditInput!]!) {
    decayRuleFieldPatch(id: $id, input: $input) {
      ...KnowledgeDecayRuleView_decayRule
    }
  }
`;

interface KnowledgeDecayRuleViewProps {
  decayRule: KnowledgeDecayRuleView_decayRule$key;
}

const KnowledgeDecayRuleView = ({ decayRule: decayRuleKey }: KnowledgeDecayRuleViewProps) => {
  const { t_i18n } = useFormatter();
  const decayRule = useFragment(knowledgeDecayRuleViewFragment, decayRuleKey);
  const [editOpen, setEditOpen] = useState(false);
  const [commitEdit] = useApiMutation<KnowledgeDecayRuleViewEditMutation>(knowledgeDecayRuleViewEditMutation);
  const filters = decayRule.decay_filters ? JSON.parse(decayRule.decay_filters) : null;
  const targetTypes = (decayRule.target_types ?? []).map((type) => t_i18n(decayRule.target_scope === 'relationship' ? `relationship_${type}` : `entity_${type}`));
  const typesOptions = (decayRule.target_types ?? []).map((type, index) => ({ value: type, label: targetTypes[index] }));

  const onEdit = (input: KnowledgeDecayRuleInput, { setSubmitting, setErrors }: FormikHelpers<KnowledgeDecayRuleFormValues>) => {
    const current: Record<string, unknown> = {
      name: decayRule.name,
      description: decayRule.description ?? '',
      order: decayRule.order,
      active: decayRule.active,
      target_types: [...(decayRule.target_types ?? [])],
      freshness_policy: decayRule.freshness_policy,
      stale_after_days: decayRule.stale_after_days,
      freshness_confidence_step: decayRule.freshness_confidence_step ?? null,
      decay_filters: decayRule.decay_filters ?? null,
    };
    const changes = Object.entries(input)
      .filter(([key]) => key !== 'target_scope')
      .filter(([key, value]) => JSON.stringify(value ?? null) !== JSON.stringify(current[key] ?? null))
      .map(([key, value]) => ({ key, value: Array.isArray(value) ? value : [value] }));
    if (changes.length === 0) {
      setSubmitting(false);
      setEditOpen(false);
      return;
    }
    commitEdit({
      variables: { id: decayRule.id, input: changes },
      onCompleted: (_, errors) => {
        setSubmitting(false);
        if (notifyPayloadErrors(errors)) return;
        setEditOpen(false);
      },
      onError: (error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
    });
  };

  return (
    <>
      {!decayRule.built_in && (
        <Box sx={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 2 }}>
          <Button startIcon={<EditOutlined />} onClick={() => setEditOpen(true)} data-testid="knowledge-decay-rule-edit">
            {t_i18n('Update')}
          </Button>
        </Box>
      )}
      {decayRule.built_in && (
        <Alert severity="info" variant="outlined" sx={{ marginBottom: 2 }}>
          {t_i18n('This built-in knowledge decay rule is shipped disabled. It can be activated or deactivated, create your own rule to change its configuration.')}
        </Alert>
      )}
      <Grid container spacing={3} data-testid="knowledge-decay-rule-view">
        <Grid item xs={6}>
          <Card title={t_i18n('Configuration')}>
            <Grid container spacing={2}>
              <Grid item xs={12}>
                <Label>{t_i18n('Description')}</Label>
                <ExpandableMarkdown source={decayRule.description} limit={300} />
              </Grid>
              <Grid item xs={12}>
                <Label>{t_i18n('Target scope')}</Label>
                {decayRule.target_scope === 'relationship' ? t_i18n('Relationships') : t_i18n('Entities')}
              </Grid>
              <Grid item xs={12}>
                <Label>{t_i18n('Target types')}</Label>
                {targetTypes.length > 0 ? targetTypes.join(', ') : t_i18n('All relationships')}
              </Grid>
              <Grid item xs={12}>
                <Label>{t_i18n('Filters')}</Label>
                <FieldOrEmpty source={decayRule.decay_filters}>
                  <FilterIconButton filters={filters} />
                </FieldOrEmpty>
              </Grid>
              <Grid item xs={6}>
                <Label>{t_i18n('Stale after (days without assertion)')}</Label>
                {decayRule.stale_after_days}
              </Grid>
              <Grid item xs={6}>
                <Label>{t_i18n('Policy for stale knowledge')}</Label>
                {t_i18n(KNOWLEDGE_FRESHNESS_POLICY_LABELS[(decayRule.freshness_policy ?? 'flag') as KnowledgeFreshnessPolicy])}
                {decayRule.freshness_policy === 'lower_confidence' ? ` (-${decayRule.freshness_confidence_step})` : ''}
              </Grid>
              <Grid item xs={6}>
                <Label>{t_i18n('Order')}</Label>
                {decayRule.order}
              </Grid>
            </Grid>
          </Card>
        </Grid>
        <Grid item xs={6}>
          <Card title={t_i18n('Impact')}>
            <span data-testid="knowledge-decay-rule-stale-count">
              {t_i18n('{count} elements currently flagged as stale by this rule', { values: { count: decayRule.staleElementsCount } })}
            </span>
          </Card>
        </Grid>
      </Grid>
      <Drawer title={t_i18n('Update a knowledge decay rule')} open={editOpen} onClose={() => setEditOpen(false)}>
        {editOpen ? (
          <KnowledgeDecayRuleForm
            isEdition
            initialFilters={filters}
            initialValues={{
              name: decayRule.name,
              description: decayRule.description ?? '',
              order: decayRule.order,
              active: decayRule.active,
              target_scope: decayRule.target_scope === 'entity' ? 'entity' : 'relationship',
              target_types: typesOptions,
              freshness_policy: (decayRule.freshness_policy ?? 'flag') as KnowledgeFreshnessPolicy,
              stale_after_days: decayRule.stale_after_days ?? 180,
              freshness_confidence_step: decayRule.freshness_confidence_step ?? 10,
            }}
            onSubmit={onEdit}
            onCancel={() => setEditOpen(false)}
          />
        ) : null}
      </Drawer>
    </>
  );
};

export default KnowledgeDecayRuleView;
