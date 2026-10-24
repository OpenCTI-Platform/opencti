import React, { ReactNode, useState } from 'react';
import { graphql } from 'react-relay';
import { useNavigate } from 'react-router';
import { Alert, Checkbox, Input, Paper, Switch, Text, Textarea } from '@filigran/design-system';
import Box from '@mui/material/Box';
import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import { DeleteOutlined } from '@mui/icons-material';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import {
  draftToInput,
  emptyCriterion,
  emptyGroup,
  emptyPathCondition,
  emptyRule,
  type IrCriterionDraft,
  type IrDraft,
  type IrGroupDraft,
  type IrRuleDraft,
  newId,
} from './irConfigTypes';
import { IR_ENTITY_TYPES, IR_KEYWORD_FIELDS, IR_RELATIONSHIP_TYPES } from './irConstants';
import { IrConditionsEditor, IrEntityPicker, IrMultiSelect, IrSelect } from './IrFields';
import type { IntelligenceRequirementConfigurationFormAddMutation } from './__generated__/IntelligenceRequirementConfigurationFormAddMutation.graphql';
import type { IntelligenceRequirementConfigurationFormUpdateMutation } from './__generated__/IntelligenceRequirementConfigurationFormUpdateMutation.graphql';

const addMutation = graphql`
  mutation IntelligenceRequirementConfigurationFormAddMutation($input: IntelligenceRequirementInput!) {
    intelligenceRequirementAdd(input: $input) {
      id
    }
  }
`;

const updateMutation = graphql`
  mutation IntelligenceRequirementConfigurationFormUpdateMutation($id: ID!, $input: IntelligenceRequirementInput!) {
    intelligenceRequirementUpdate(id: $id, input: $input) {
      id
      name
    }
  }
`;

const Block = ({ step, title, subtitle, action, children }: { step: number; title: string; subtitle: string; action?: ReactNode; children: ReactNode }) => (
  <Paper padding={24} style={{ marginBottom: 16 }}>
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 2 }}>
      <Box sx={{ width: 24, height: 24, borderRadius: '50%', border: '1px solid', borderColor: 'primary.main', color: 'primary.main', display: 'grid', placeItems: 'center', fontSize: 12, fontWeight: 600 }}>{step}</Box>
      <Text as="span" variant="title-sm">{title}</Text>
      <Text as="span" variant="content-caption" style={{ opacity: 0.7 }}>{subtitle}</Text>
      <Box sx={{ flex: 1 }} />
      {action}
    </Box>
    {children}
  </Paper>
);

const Row = ({ children, columns }: { children: ReactNode; columns: string }) => (
  <Box sx={{ display: 'grid', gridTemplateColumns: columns, gap: 2, alignItems: 'end', mb: 2 }}>{children}</Box>
);

const SubCard = ({ children, onDelete, highlight }: { children: ReactNode; onDelete: () => void; highlight?: boolean }) => {
  const { t_i18n } = useFormatter();
  return (
    <Box sx={{ border: '1px solid', borderColor: highlight ? 'error.main' : 'divider', borderRadius: 1, p: 2, mb: 1.5, position: 'relative' }}>
      <Box sx={{ position: 'absolute', top: 8, right: 8 }}>
        <IconButton aria-label={t_i18n('Delete')} onClick={onDelete}><DeleteOutlined fontSize="small" /></IconButton>
      </Box>
      <Box sx={{ pr: 5 }}>{children}</Box>
    </Box>
  );
};

interface IntelligenceRequirementConfigurationFormProps {
  initialDraft: IrDraft;
  irId?: string;
}

const IntelligenceRequirementConfigurationForm = ({ initialDraft, irId }: IntelligenceRequirementConfigurationFormProps) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const [draft, setDraft] = useState<IrDraft>(initialDraft);
  const [error, setError] = useState<string | null>(null);
  const [commitAdd, adding] = useApiMutation<IntelligenceRequirementConfigurationFormAddMutation>(addMutation);
  const [commitUpdate, updating] = useApiMutation<IntelligenceRequirementConfigurationFormUpdateMutation>(updateMutation, undefined, { successMessage: t_i18n('Configuration saved') });

  const set = (patch: Partial<IrDraft>) => setDraft((d) => ({ ...d, ...patch }));
  const setGroup = (id: string, patch: Partial<IrGroupDraft>) => set({ groups: draft.groups.map((g) => (g.id === id ? { ...g, ...patch } : g)) });
  const setCriterion = (id: string, patch: Partial<IrCriterionDraft>) => set({ criteria: draft.criteria.map((c) => (c.id === id ? { ...c, ...patch } : c)) });
  const setRule = (id: string, patch: Partial<IrRuleDraft>) => set({ rules: draft.rules.map((r) => (r.id === id ? { ...r, ...patch } : r)) });

  const typeOptions = IR_ENTITY_TYPES.map((t) => ({ value: t, label: t_i18n(`entity_${t}`) }));
  const relationshipOptions = IR_RELATIONSHIP_TYPES.map((r) => ({ value: r, label: r }));
  const groupOptions = draft.groups.map((g) => ({ value: g.id, label: g.name || g.id }));
  const criterionOptions = draft.criteria.map((c) => ({ value: c.id, label: c.name || c.id }));
  const directionOptions = [
    { value: 'outgoing', label: t_i18n('Outgoing (anchor → target)') },
    { value: 'incoming', label: t_i18n('Incoming (target → anchor)') },
    { value: 'both', label: t_i18n('Both directions') },
  ];

  const save = () => {
    setError(null);
    if (!draft.name.trim() || !draft.question.trim()) {
      setError(t_i18n('The name and the question are required'));
      return;
    }
    const input = draftToInput(draft);
    if (irId) {
      commitUpdate({ variables: { id: irId, input: input as never }, onError: (e) => setError(e.message) });
    } else {
      commitAdd({
        variables: { input: input as never },
        onCompleted: (response) => {
          const id = response.intelligenceRequirementAdd?.id;
          if (id) navigate(`/dashboard/intelligence_requirements/${id}`);
        },
        onError: (e) => setError(e.message),
      });
    }
  };

  return (
    <Box sx={{ maxWidth: 1100 }}>
      {/* Identity */}
      <Paper padding={24} style={{ marginBottom: 16 }}>
        <Row columns="2fr 1fr 1fr">
          <Input label={t_i18n('Name')} required value={draft.name} onChange={(e) => set({ name: e.target.value })} />
          <IrSelect
            label={t_i18n('Priority')}
            value={draft.priority}
            options={['critical', 'high', 'medium', 'low'].map((p) => ({ value: p, label: t_i18n(p) }))}
            onChange={(v) => set({ priority: v as IrDraft['priority'] })}
          />
          <IrSelect
            label={t_i18n('Status')}
            value={draft.status}
            options={[{ value: 'active', label: t_i18n('Active') }, { value: 'paused', label: t_i18n('Paused') }]}
            onChange={(v) => set({ status: v as IrDraft['status'] })}
          />
        </Row>
        <Row columns="1fr">
          <Textarea label={t_i18n('Description')} value={draft.description} onChange={(e) => set({ description: e.target.value })} />
        </Row>
      </Paper>

      {/* 1. Question */}
      <Block step={1} title={t_i18n('Question')} subtitle={t_i18n('why this requirement exists, and its key intelligence questions')}>
        <Row columns="1fr">
          <Textarea label={t_i18n('Intelligence question')} required value={draft.question} onChange={(e) => set({ question: e.target.value })} />
        </Row>
        {draft.kiqs.map((kiq) => (
          <SubCard key={kiq.id} onDelete={() => set({ kiqs: draft.kiqs.filter((k) => k.id !== kiq.id) })}>
            <Row columns="2fr 1fr">
              <Input label={t_i18n('Key intelligence question')} value={kiq.text} onChange={(e) => set({ kiqs: draft.kiqs.map((k) => (k.id === kiq.id ? { ...k, text: e.target.value } : k)) })} />
              <IrMultiSelect
                label={t_i18n('Answered by criteria')}
                values={kiq.criteria_ids}
                options={criterionOptions}
                onChange={(v) => set({ kiqs: draft.kiqs.map((k) => (k.id === kiq.id ? { ...k, criteria_ids: v } : k)) })}
              />
            </Row>
          </SubCard>
        ))}
        <Button variant="tertiary" size="small" onClick={() => set({ kiqs: [...draft.kiqs, { id: newId('kiq'), text: '', criteria_ids: [] }] })}>{t_i18n('Add a key intelligence question')}</Button>
      </Block>

      {/* 2. Subjects */}
      <Block
        step={2}
        title={t_i18n('Subjects')}
        subtitle={t_i18n('named groups of anchors: a list of entities, a dynamic filter or keywords')}
        action={<Button variant="secondary" size="small" onClick={() => set({ groups: [...draft.groups, emptyGroup()] })}>{t_i18n('Add a group')}</Button>}
      >
        {draft.groups.map((group) => (
          <SubCard key={group.id} onDelete={() => set({ groups: draft.groups.filter((g) => g.id !== group.id) })}>
            <Row columns="2fr 1fr 1fr">
              <Input label={t_i18n('Group name')} value={group.name} onChange={(e) => setGroup(group.id, { name: e.target.value })} />
              <IrSelect
                label={t_i18n('Kind')}
                value={group.kind}
                options={[{ value: 'list', label: t_i18n('List of entities') }, { value: 'filter', label: t_i18n('Dynamic filter') }, { value: 'keywords', label: t_i18n('Keywords') }]}
                onChange={(v) => setGroup(group.id, { kind: v as IrGroupDraft['kind'] })}
              />
              <IrSelect
                label={t_i18n('Role')}
                value={group.role}
                options={[{ value: 'entry', label: t_i18n('Entry') }, { value: 'context', label: t_i18n('Context') }, { value: 'both', label: t_i18n('Entry and context') }]}
                onChange={(v) => setGroup(group.id, { role: v as IrGroupDraft['role'] })}
              />
            </Row>
            {group.kind === 'list' && <IrEntityPicker label={t_i18n('Entities')} value={group.entities} onChange={(entities) => setGroup(group.id, { entities })} />}
            {group.kind === 'filter' && <IrConditionsEditor conditions={group.conditions} onChange={(conditions) => setGroup(group.id, { conditions })} />}
            {group.kind === 'keywords' && (
              <IrMultiSelect
                label={t_i18n('Keywords')}
                values={group.keywords}
                options={group.keywords.map((k) => ({ value: k, label: k }))}
                allowCustom
                placeholder={t_i18n('Type a keyword and press Enter')}
                onChange={(keywords) => setGroup(group.id, { keywords })}
              />
            )}
          </SubCard>
        ))}
      </Block>

      {/* 3. Scope */}
      <Block
        step={3}
        title={t_i18n('Scope')}
        subtitle={t_i18n('entry criteria: what makes an entity enter the requirement')}
        action={<Button variant="secondary" size="small" onClick={() => set({ criteria: [...draft.criteria, emptyCriterion(draft.groups)] })}>{t_i18n('Add a criterion')}</Button>}
      >
        {draft.criteria.map((criterion) => (
          <SubCard key={criterion.id} onDelete={() => set({ criteria: draft.criteria.filter((c) => c.id !== criterion.id) })}>
            <Row columns="2fr 1fr 1fr">
              <Input label={t_i18n('Criterion name')} value={criterion.name} onChange={(e) => setCriterion(criterion.id, { name: e.target.value })} />
              <IrSelect
                label={t_i18n('Kind')}
                value={criterion.kind}
                options={[{ value: 'graph', label: t_i18n('Path in the graph') }, { value: 'attribute', label: t_i18n('Attributes (zero hop)') }, { value: 'keywords', label: t_i18n('Keywords') }]}
                onChange={(v) => setCriterion(criterion.id, { kind: v as IrCriterionDraft['kind'] })}
              />
              <IrSelect
                label={t_i18n('Mode')}
                value={criterion.mode}
                options={[{ value: 'auto', label: t_i18n('Auto-include') }, { value: 'propose', label: t_i18n('Propose') }, { value: 'off', label: t_i18n('Off') }]}
                onChange={(v) => setCriterion(criterion.id, { mode: v as IrCriterionDraft['mode'] })}
              />
            </Row>
            {criterion.kind === 'graph' && (
              <>
                <Row columns="1fr 1fr">
                  <IrMultiSelect label={t_i18n('From subject groups')} values={criterion.from_group_ids} options={groupOptions} onChange={(v) => setCriterion(criterion.id, { from_group_ids: v })} />
                  <Checkbox
                    label={t_i18n('Also from the entities already in the requirement (second hop)')}
                    checked={criterion.from_in_requirement}
                    onCheckedChange={(checked) => setCriterion(criterion.id, { from_in_requirement: checked === true })}
                  />
                </Row>
                <Row columns="1fr 1fr 1fr">
                  <IrMultiSelect label={t_i18n('Relationship types')} values={criterion.relationship_types} options={relationshipOptions} onChange={(v) => setCriterion(criterion.id, { relationship_types: v })} />
                  <IrSelect label={t_i18n('Direction')} value={criterion.direction} options={directionOptions} onChange={(v) => setCriterion(criterion.id, { direction: v as IrCriterionDraft['direction'] })} />
                  <IrMultiSelect label={t_i18n('Target types')} values={criterion.target_types} options={typeOptions} onChange={(v) => setCriterion(criterion.id, { target_types: v })} />
                </Row>
              </>
            )}
            {criterion.kind === 'attribute' && (
              <Row columns="1fr">
                <IrMultiSelect label={t_i18n('Entity types')} values={criterion.target_types} options={typeOptions} onChange={(v) => setCriterion(criterion.id, { target_types: v })} />
              </Row>
            )}
            {criterion.kind === 'keywords' && (
              <Row columns="1fr 1fr 1fr">
                <IrMultiSelect
                  label={t_i18n('Keyword groups')}
                  values={criterion.from_group_ids}
                  options={draft.groups.filter((g) => g.kind === 'keywords').map((g) => ({ value: g.id, label: g.name || g.id }))}
                  onChange={(v) => setCriterion(criterion.id, { from_group_ids: v })}
                />
                <IrMultiSelect label={t_i18n('Search in')} values={criterion.keyword_fields} options={IR_KEYWORD_FIELDS.map((f) => ({ value: f, label: t_i18n(f) }))} onChange={(v) => setCriterion(criterion.id, { keyword_fields: v })} />
                <IrMultiSelect label={t_i18n('Entity types to propose')} values={criterion.target_types} options={typeOptions} onChange={(v) => setCriterion(criterion.id, { target_types: v })} />
              </Row>
            )}
            <Text as="div" variant="content-caption" style={{ marginBottom: 8, opacity: 0.8 }}>{t_i18n('Target filters (optional)')}</Text>
            <IrConditionsEditor conditions={criterion.target_conditions} onChange={(conditions) => setCriterion(criterion.id, { target_conditions: conditions })} />
          </SubCard>
        ))}
      </Block>

      {/* 4. Relevance */}
      <Block
        step={4}
        title={t_i18n('Relevance')}
        subtitle={t_i18n('scoring rules: applies to · if · then ± points')}
        action={<Button variant="secondary" size="small" onClick={() => set({ rules: [...draft.rules, emptyRule()] })}>{t_i18n('Add a rule')}</Button>}
      >
        {draft.rules.map((rule) => (
          <SubCard key={rule.id} highlight={rule.required} onDelete={() => set({ rules: draft.rules.filter((r) => r.id !== rule.id) })}>
            <Row columns="2fr 0.6fr 1fr 1fr">
              <Input label={t_i18n('Rule name')} value={rule.name} onChange={(e) => setRule(rule.id, { name: e.target.value })} />
              <Input label={t_i18n('Points')} type="number" value={String(rule.points)} onChange={(e) => setRule(rule.id, { points: Number.parseInt(e.target.value || '0', 10) })} />
              <Checkbox
                label={t_i18n('Required (excludes if not met)')}
                checked={rule.required}
                onCheckedChange={(checked) => setRule(rule.id, { required: checked === true })}
              />
              <Switch label={t_i18n('Enabled')} checked={rule.enabled} onCheckedChange={(checked) => setRule(rule.id, { enabled: checked })} />
            </Row>
            <Text as="div" variant="content-compact-bold" style={{ marginBottom: 8 }}>{t_i18n('Applies to')}</Text>
            <Row columns="1fr 1fr">
              <IrMultiSelect label={t_i18n('Entity types (empty = any)')} values={rule.applies_to_types} options={typeOptions} onChange={(v) => setRule(rule.id, { applies_to_types: v })} />
              <IrSelect
                label={t_i18n('Entered by')}
                value={rule.applies_to_criterion_id ?? 'any'}
                options={[{ value: 'any', label: t_i18n('Any criterion') }, ...criterionOptions]}
                onChange={(v) => setRule(rule.id, { applies_to_criterion_id: v === 'any' ? null : v })}
              />
            </Row>
            <Text as="div" variant="content-compact-bold" style={{ marginBottom: 8 }}>{t_i18n('If')}</Text>
            <IrConditionsEditor conditions={rule.conditions} onChange={(conditions) => setRule(rule.id, { conditions })} />
            <Box sx={{ mt: 2 }}>
              <Checkbox
                label={t_i18n('Path condition: linked to an entity that has a relationship toward…')}
                checked={!!rule.path_condition}
                onCheckedChange={(checked) => setRule(rule.id, { path_condition: checked === true ? emptyPathCondition() : null })}
              />
            </Box>
            {rule.path_condition && (
              <Box sx={{ mt: 1.5 }}>
                <Row columns="1fr 1fr 1fr">
                  <IrMultiSelect
                    label={t_i18n('Linked by')}
                    values={rule.path_condition.relationship_types}
                    options={relationshipOptions}
                    onChange={(v) => setRule(rule.id, { path_condition: { ...rule.path_condition!, relationship_types: v } })}
                  />
                  <IrSelect
                    label={t_i18n('Direction')}
                    value={rule.path_condition.direction}
                    options={directionOptions}
                    onChange={(v) => setRule(rule.id, { path_condition: { ...rule.path_condition!, direction: v as IrCriterionDraft['direction'] } })}
                  />
                  <IrSelect
                    label={t_i18n('to an entity that')}
                    value={rule.path_condition.target_relationship_type}
                    options={relationshipOptions}
                    onChange={(v) => setRule(rule.id, { path_condition: { ...rule.path_condition!, target_relationship_type: v } })}
                  />
                </Row>
                <IrEntityPicker label={t_i18n('one of')} value={rule.path_condition.targets} onChange={(targets) => setRule(rule.id, { path_condition: { ...rule.path_condition!, targets } })} />
              </Box>
            )}
          </SubCard>
        ))}
      </Block>

      {/* 5. Follow-up */}
      <Paper padding={24} style={{ marginBottom: 16 }}>
        <Row columns="1fr 1fr 2fr">
          <Input label={t_i18n('Score thresholds (inbox)')} value={draft.thresholds} onChange={(e) => set({ thresholds: e.target.value })} />
          <Input label={t_i18n('Rescan in days')} type="number" value={String(draft.rescan_days)} onChange={(e) => set({ rescan_days: Number.parseInt(e.target.value || '0', 10) })} disabled={!!irId} />
          <div />
        </Row>
      </Paper>

      {error && <Box sx={{ mb: 2 }}><Alert severity="error" title={error} /></Box>}
      <Box sx={{ display: 'flex', gap: 1, justifyContent: 'flex-end', mb: 4 }}>
        <Button variant="secondary" onClick={() => navigate(irId ? `/dashboard/intelligence_requirements/${irId}` : '/dashboard/intelligence_requirements')}>{t_i18n('Cancel')}</Button>
        <Button onClick={save} disabled={adding || updating}>{irId ? t_i18n('Save configuration') : t_i18n('Create')}</Button>
      </Box>
    </Box>
  );
};

export default IntelligenceRequirementConfigurationForm;
