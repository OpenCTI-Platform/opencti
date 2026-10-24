import React from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { useNavigate, useParams } from 'react-router';
import { Chip, Paper, Text } from '@filigran/design-system';
import Box from '@mui/material/Box';
import Button from '@common/button/Button';
import Breadcrumbs from '../../../components/Breadcrumbs';
import { useFormatter } from '../../../components/i18n';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import { PRIORITY_SEVERITY } from './IntelligenceRequirements';
import type { IntelligenceRequirementQuery } from './__generated__/IntelligenceRequirementQuery.graphql';

// Page of a requirement. Step 5 of the proof of concept adds the Overview, Entities and Inbox tabs.

const requirementQuery = graphql`
  query IntelligenceRequirementQuery($id: ID!) {
    intelligenceRequirement(id: $id) {
      id
      name
      ir_question
      ir_priority
      ir_status
      ir_subject_groups { id name kind keywords entities { id representative { main } } }
    }
  }
`;

const IntelligenceRequirement = () => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const { irId } = useParams() as { irId: string };
  const { setTitle } = useConnectedDocumentModifier();
  const data = useLazyLoadQuery<IntelligenceRequirementQuery>(requirementQuery, { id: irId }, { fetchPolicy: 'network-only' });
  const ir = data.intelligenceRequirement;
  setTitle(ir?.name ?? t_i18n('PIR (generic)'));
  if (!ir) return <div>{t_i18n('This intelligence requirement does not exist')}</div>;
  return (
    <>
      <Breadcrumbs elements={[{ label: t_i18n('PIR (generic)'), link: '/dashboard/intelligence_requirements' }, { label: ir.name, current: true }]} />
      <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 2, mb: 2 }}>
        <Box sx={{ flex: 1 }}>
          <Text as="h1" variant="title-md">{ir.name}</Text>
          <Text as="div" variant="content-base" style={{ opacity: 0.8, marginTop: 4 }}>{`“${ir.ir_question}”`}</Text>
          <Box sx={{ display: 'flex', gap: 1, mt: 1 }}>
            <Chip label={t_i18n(ir.ir_priority)} severity={PRIORITY_SEVERITY[ir.ir_priority]} />
            <Chip label={t_i18n(ir.ir_status === 'active' ? 'Active' : 'Paused')} />
          </Box>
        </Box>
        <Button variant="secondary" onClick={() => navigate(`/dashboard/intelligence_requirements/${ir.id}/configuration`)}>{t_i18n('Configuration')}</Button>
      </Box>
      <Paper padding={16}>
        <Box sx={{ display: 'flex', gap: 3, flexWrap: 'wrap' }}>
          {ir.ir_subject_groups.map((g) => (
            <Box key={g.id} sx={{ display: 'flex', gap: 1, alignItems: 'center', flexWrap: 'wrap' }}>
              <Text as="span" variant="content-caption" style={{ textTransform: 'uppercase', opacity: 0.7 }}>{g.name}</Text>
              {g.kind === 'keywords'
                ? g.keywords.map((k) => <Chip key={k} label={`#${k}`} severity="info" size="sm" />)
                : g.entities.map((e) => <Chip key={e.id} label={e.representative.main} severity="info" size="sm" />)}
              {g.kind === 'filter' && <Chip label={t_i18n('Dynamic filter')} size="sm" />}
            </Box>
          ))}
        </Box>
      </Paper>
    </>
  );
};

export default IntelligenceRequirement;
