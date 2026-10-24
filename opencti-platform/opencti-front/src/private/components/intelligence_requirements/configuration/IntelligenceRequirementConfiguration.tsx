import React from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { useParams } from 'react-router';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { useFormatter } from '../../../../components/i18n';
import useConnectedDocumentModifier from '../../../../utils/hooks/useConnectedDocumentModifier';
import IntelligenceRequirementConfigurationForm from './IntelligenceRequirementConfigurationForm';
import { emptyDraft, type IrDraft } from './irConfigTypes';
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
      ir_kiqs { id text criteria_ids }
      ir_subject_groups {
        id
        name
        kind
        role
        filters
        keywords
        entities { id entity_type representative { main } }
      }
      ir_scope_criteria {
        id
        name
        kind
        from_group_ids
        from_in_requirement
        relationship_types
        direction
        target_types
        target_filters
        keyword_fields
        mode
      }
      ir_relevance_rules {
        id
        name
        applies_to_types
        applies_to_criterion_id
        filters
        points
        required
        enabled
        path_condition {
          relationship_types
          direction
          target_relationship_type
          targets { id entity_type representative { main } }
        }
      }
    }
  }
`;

type Ir = NonNullable<IntelligenceRequirementConfigurationQuery$data['intelligenceRequirement']>;

const toOption = (e: { id: string; entity_type: string; representative: { main: string } }) => ({ value: e.id, label: e.representative.main, type: e.entity_type });

const nodeToDraft = (ir: Ir): IrDraft => ({
  name: ir.name,
  description: ir.description ?? '',
  question: ir.ir_question,
  priority: ir.ir_priority,
  status: ir.ir_status,
  thresholds: ir.ir_thresholds.join(', '),
  rescan_days: ir.ir_rescan_days,
  kiqs: ir.ir_kiqs.map((k) => ({ id: k.id, text: k.text, criteria_ids: [...k.criteria_ids] })),
  groups: ir.ir_subject_groups.map((g) => ({
    id: g.id,
    name: g.name,
    kind: g.kind,
    role: g.role,
    entities: g.entities.map(toOption),
    filters: g.filters ?? null,
    keywords: [...g.keywords],
  })),
  criteria: ir.ir_scope_criteria.map((c) => ({
    id: c.id,
    name: c.name,
    kind: c.kind,
    from_group_ids: [...c.from_group_ids],
    from_in_requirement: c.from_in_requirement,
    relationship_types: [...c.relationship_types],
    direction: c.direction,
    target_types: [...c.target_types],
    target_filters: c.target_filters ?? null,
    keyword_fields: [...c.keyword_fields],
    mode: c.mode,
  })),
  rules: ir.ir_relevance_rules.map((r) => ({
    id: r.id,
    name: r.name,
    applies_to_types: [...r.applies_to_types],
    applies_to_criterion_id: r.applies_to_criterion_id ?? null,
    filters: r.filters ?? null,
    path_condition: r.path_condition ? {
      relationship_types: [...r.path_condition.relationship_types],
      direction: r.path_condition.direction,
      target_relationship_type: r.path_condition.target_relationship_type,
      targets: r.path_condition.targets.map(toOption),
    } : null,
    points: r.points,
    required: r.required,
    enabled: r.enabled,
  })),
});

const EditConfiguration = ({ irId }: { irId: string }) => {
  const { t_i18n } = useFormatter();
  const data = useLazyLoadQuery<IntelligenceRequirementConfigurationQuery>(configurationQuery, { id: irId }, { fetchPolicy: 'network-only' });
  const ir = data.intelligenceRequirement;
  if (!ir) return <div>{t_i18n('This intelligence requirement does not exist')}</div>;
  return (
    <>
      <Breadcrumbs elements={[
        { label: t_i18n('PIR (generic)'), link: '/dashboard/intelligence_requirements' },
        { label: ir.name, link: `/dashboard/intelligence_requirements/${ir.id}` },
        { label: t_i18n('Configuration'), current: true },
      ]}
      />
      <IntelligenceRequirementConfigurationForm initialDraft={nodeToDraft(ir)} irId={ir.id} />
    </>
  );
};

const IntelligenceRequirementConfiguration = () => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  const { irId } = useParams() as { irId?: string };
  setTitle(t_i18n('PIR (generic)'));
  if (irId) return <EditConfiguration irId={irId} />;
  return (
    <>
      <Breadcrumbs elements={[
        { label: t_i18n('PIR (generic)'), link: '/dashboard/intelligence_requirements' },
        { label: t_i18n('New requirement'), current: true },
      ]}
      />
      <IntelligenceRequirementConfigurationForm initialDraft={emptyDraft()} />
    </>
  );
};

export default IntelligenceRequirementConfiguration;
