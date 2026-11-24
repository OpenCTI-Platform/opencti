import React, { useState } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { Text } from '@filigran/design-system';
import Box from '@mui/material/Box';
import Button from '@common/button/Button';
import { useFormatter } from '../../../../components/i18n';
import IntelligenceRequirementConfigurationForm from './IntelligenceRequirementConfigurationForm';
import { type IrCriterionKind, type IrCriterionMode, type IrDirection, type IrDraft, type IrGroupKind, type IrGroupRole, type IrPriority, type IrStatus } from './irConfigTypes';
import { type IrConfigView, readConfigView, writeConfigView } from './irSentence';
import type { IntelligenceRequirementConfigurationQuery, IntelligenceRequirementConfigurationQuery$data } from './__generated__/IntelligenceRequirementConfigurationQuery.graphql';

const configurationQuery = graphql`
  query IntelligenceRequirementConfigurationQuery($id: ID!) {
    intelligenceRequirement(id: $id) {
      id
      name
      description
      ir_question
      ir_priority
      ir_status
      ir_thresholds
      ir_rescan_days
      ir_brief_frequency
      ir_kiqs { id text criteria_ids }
      ir_subject_groups {
        id
        name
        kind
        role
        filters
        keywords
        exclude_keywords
        entities { id entity_type representative { main } }
      }
      ir_scope_criteria {
        id
        name
        kind
        from_group_ids
        from_in_requirement
        from_types
        relationship_types
        direction
        target_types
        target_filters
        keyword_fields
        mode
        conditions {
          id
          name
          applies_to_types
          filters
          link { relationship_types group_ids }
          path_condition {
            relationship_types
            direction
            intermediate_types
            target_relationship_type
            target_group_ids
            targets { id entity_type representative { main } }
          }
        }
      }
      ir_relevance_rules {
        id
        name
        applies_to_types
        applies_to_criterion_id
        filters
        points
        enabled
        link { relationship_types group_ids }
        path_condition {
          relationship_types
          direction
          intermediate_types
          target_relationship_type
          target_group_ids
          targets { id entity_type representative { main } }
        }
      }
    }
  }
`;

type Ir = NonNullable<IntelligenceRequirementConfigurationQuery$data['intelligenceRequirement']>;

const toOption = (e: { id: string; entity_type: string; representative: { main: string } }) => ({ value: e.id, label: e.representative.main, type: e.entity_type });

type IrPathCondition = NonNullable<Ir['ir_relevance_rules'][number]['path_condition']>;

const pathToDraft = (path: IrPathCondition | null | undefined) => (path ? {
  relationship_types: [...path.relationship_types],
  direction: path.direction as IrDirection,
  intermediate_types: [...(path.intermediate_types ?? [])],
  target_relationship_type: path.target_relationship_type,
  targets: path.targets.map(toOption),
  target_group_ids: [...path.target_group_ids],
} : null);

const linkToDraft = (link: { relationship_types: readonly string[]; group_ids: readonly string[] } | null | undefined) => (link
  ? { relationship_types: [...link.relationship_types], group_ids: [...link.group_ids] }
  : null);

const nodeToDraft = (ir: Ir): IrDraft => ({
  name: ir.name,
  description: ir.description ?? '',
  question: ir.ir_question,
  priority: ir.ir_priority as IrPriority,
  status: ir.ir_status as IrStatus,
  thresholds: ir.ir_thresholds.join(', '),
  rescan_days: ir.ir_rescan_days,
  brief_frequency: ir.ir_brief_frequency as IrDraft['brief_frequency'],
  kiqs: ir.ir_kiqs.map((k) => ({ id: k.id, text: k.text, criteria_ids: [...k.criteria_ids] })),
  groups: ir.ir_subject_groups.map((g) => ({
    id: g.id,
    name: g.name,
    kind: g.kind as IrGroupKind,
    role: g.role as IrGroupRole,
    entities: g.entities.map(toOption),
    filters: g.filters ?? null,
    keywords: [...g.keywords],
    exclude_keywords: [...(g.exclude_keywords ?? [])],
  })),
  criteria: ir.ir_scope_criteria.map((c) => ({
    id: c.id,
    name: c.name,
    kind: c.kind as IrCriterionKind,
    from_group_ids: [...c.from_group_ids],
    from_in_requirement: c.from_in_requirement,
    from_types: [...(c.from_types ?? [])],
    relationship_types: [...c.relationship_types],
    direction: c.direction as IrDirection,
    target_types: [...c.target_types],
    target_filters: c.target_filters ?? null,
    keyword_fields: [...c.keyword_fields],
    mode: c.mode as IrCriterionMode,
    conditions: c.conditions.map((k) => ({
      id: k.id,
      name: k.name,
      applies_to_types: [...k.applies_to_types],
      filters: k.filters ?? null,
      link: linkToDraft(k.link),
      path_condition: pathToDraft(k.path_condition),
    })),
  })),
  rules: ir.ir_relevance_rules.map((r) => ({
    id: r.id,
    name: r.name,
    applies_to_types: [...r.applies_to_types],
    applies_to_criterion_id: r.applies_to_criterion_id ?? null,
    filters: r.filters ?? null,
    link: linkToDraft(r.link),
    path_condition: pathToDraft(r.path_condition),
    points: r.points,
    enabled: r.enabled,
  })),
});

// How the scope criteria are written: the form fields, or sentences (the same configuration either way)
export const IrViewToggle = ({ view, onChange }: { view: IrConfigView; onChange: (view: IrConfigView) => void }) => {
  const { t_i18n } = useFormatter();
  return (
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
      <Text as="span" variant="content-caption" style={{ opacity: 0.8 }}>{t_i18n('Write the scope criteria as')}</Text>
      <Button variant={view === 'fields' ? 'secondary' : 'tertiary'} size="small" selected={view === 'fields'} onClick={() => onChange('fields')}>{t_i18n('Form fields')}</Button>
      <Button variant={view === 'sentence' ? 'secondary' : 'tertiary'} size="small" selected={view === 'sentence'} onClick={() => onChange('sentence')}>{t_i18n('Sentences')}</Button>
    </Box>
  );
};

// The Configuration tab of a requirement: rendered under its header and tabs (IntelligenceRequirement), which carry the breadcrumbs
export const IntelligenceRequirementConfigurationTab = ({ irId }: { irId: string }) => {
  const { t_i18n } = useFormatter();
  const [view, setView] = useState<IrConfigView>(() => readConfigView(irId));
  const changeView = (next: IrConfigView) => {
    setView(next);
    writeConfigView(irId, next);
  };
  const data = useLazyLoadQuery<IntelligenceRequirementConfigurationQuery>(configurationQuery, { id: irId }, { fetchPolicy: 'network-only' });
  const ir = data.intelligenceRequirement;
  if (!ir) return <div>{t_i18n('This intelligence requirement does not exist')}</div>;
  return (
    <>
      <IrViewToggle view={view} onChange={changeView} />
      <IntelligenceRequirementConfigurationForm initialDraft={nodeToDraft(ir)} irId={ir.id} view={view} />
    </>
  );
};
