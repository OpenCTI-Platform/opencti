import React from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { useNavigate } from 'react-router';
import { Chip, Paper, Text } from '@filigran/design-system';
import Box from '@mui/material/Box';
import Button from '@common/button/Button';
import Breadcrumbs from '../../../components/Breadcrumbs';
import { useFormatter } from '../../../components/i18n';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import type { IntelligenceRequirementsListQuery } from './__generated__/IntelligenceRequirementsListQuery.graphql';

const listQuery = graphql`
  query IntelligenceRequirementsListQuery {
    intelligenceRequirements(first: 200, orderBy: created_at, orderMode: desc) {
      edges {
        node {
          id
          name
          ir_question
          ir_priority
          ir_status
          created_at
          ir_subject_groups { id }
          ir_scope_criteria { id }
          ir_relevance_rules { id }
        }
      }
    }
  }
`;

export const PRIORITY_SEVERITY: Record<string, 'critical' | 'high' | 'medium' | 'low'> = { critical: 'critical', high: 'high', medium: 'medium', low: 'low' };

const IntelligenceRequirements = () => {
  const { t_i18n, fldt } = useFormatter();
  const navigate = useNavigate();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('PIR (generic)'));
  const data = useLazyLoadQuery<IntelligenceRequirementsListQuery>(listQuery, {}, { fetchPolicy: 'network-only' });
  const requirements = (data.intelligenceRequirements?.edges ?? []).map((e) => e.node);
  return (
    <>
      <Breadcrumbs elements={[{ label: t_i18n('PIR (generic)'), current: true }]} />
      <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
        <Text as="span" variant="content-caption" style={{ opacity: 0.8 }}>
          {t_i18n('Proof of concept: a generic requirement in four blocks (question, subjects, scope, relevance).')}
        </Text>
        <Box sx={{ flex: 1 }} />
        <Button onClick={() => navigate('/dashboard/intelligence_requirements/new')}>{t_i18n('Create a requirement')}</Button>
      </Box>
      <Paper padding={0}>
        {requirements.length === 0 && <Box sx={{ p: 3 }}><Text as="span" variant="content-base">{t_i18n('No requirement yet.')}</Text></Box>}
        {requirements.map((ir) => (
          <Box
            key={ir.id}
            onClick={() => navigate(`/dashboard/intelligence_requirements/${ir.id}`)}
            sx={{ display: 'grid', gridTemplateColumns: '1fr 110px 90px 220px 160px', gap: 2, alignItems: 'center', px: 3, py: 1.5, cursor: 'pointer', borderBottom: '1px solid', borderColor: 'divider', '&:hover': { bgcolor: 'action.hover' } }}
          >
            <Box>
              <Text as="div" variant="content-base-bold">{ir.name}</Text>
              <Text as="div" variant="content-caption" style={{ opacity: 0.7 }}>{ir.ir_question}</Text>
            </Box>
            <Chip label={t_i18n(ir.ir_priority)} severity={PRIORITY_SEVERITY[ir.ir_priority]} />
            <Chip label={t_i18n(ir.ir_status === 'active' ? 'Active' : 'Paused')} />
            <Text as="span" variant="content-caption">
              {`${ir.ir_subject_groups.length} ${t_i18n('groups')} · ${ir.ir_scope_criteria.length} ${t_i18n('criteria')} · ${ir.ir_relevance_rules.length} ${t_i18n('rules')}`}
            </Text>
            <Text as="span" variant="content-caption">{fldt(ir.created_at)}</Text>
          </Box>
        ))}
      </Paper>
    </>
  );
};

export default IntelligenceRequirements;
