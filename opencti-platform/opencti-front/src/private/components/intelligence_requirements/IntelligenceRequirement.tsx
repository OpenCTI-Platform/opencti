import React, { useState } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { Link, Route, Routes, useLocation, useNavigate, useParams } from 'react-router';
import { Badge, Chip, Paper, Tabs, TabsList, TabsTrigger, Text } from '@filigran/design-system';
import Box from '@mui/material/Box';
import Button from '@common/button/Button';
import Breadcrumbs from '../../../components/Breadcrumbs';
import { useFormatter } from '../../../components/i18n';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import { PRIORITY_SEVERITY } from './IntelligenceRequirementsCards';
import IrOverview from './outputs/IrOverview';
import IrEntities from './outputs/IrEntities';
import IrInbox from './outputs/IrInbox';
import IrProcessing from './outputs/IrProcessing';
import IrAiInsight from './IrAiInsight';
import IrDeleteDialog from './IrDeleteDialog';
import type { IntelligenceRequirementQuery } from './__generated__/IntelligenceRequirementQuery.graphql';

// Page of a requirement: the same output screens for every question (Overview, Entities, Inbox).

const requirementQuery = graphql`
  query IntelligenceRequirementQuery($id: ID!) {
    intelligenceRequirement(id: $id) {
      id
      name
      ir_question
      ir_priority
      ir_status
      ir_inbox_open_count
      ir_subject_groups { id name kind keywords entities { id representative { main } } }
    }
  }
`;

const IntelligenceRequirement = () => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const { irId } = useParams() as { irId: string };
  const { pathname } = useLocation();
  const { setTitle } = useConnectedDocumentModifier();
  const [deleting, setDeleting] = useState(false);
  const data = useLazyLoadQuery<IntelligenceRequirementQuery>(requirementQuery, { id: irId }, { fetchPolicy: 'network-only' });
  const ir = data.intelligenceRequirement;
  setTitle(ir?.name ?? t_i18n('PIR (generic)'));
  if (!ir) return <div>{t_i18n('This intelligence requirement does not exist')}</div>;
  const base = `/dashboard/intelligence_requirements/${ir.id}`;
  let tab = 'overview';
  if (pathname.endsWith('/entities')) tab = 'entities';
  if (pathname.endsWith('/inbox')) tab = 'inbox';
  if (pathname.endsWith('/processing')) tab = 'processing';
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
        <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
          <IrAiInsight irId={ir.id} />
          <Button variant="secondary" onClick={() => navigate(`/dashboard/intelligence_requirements/${ir.id}/configuration`)}>{t_i18n('Configuration')}</Button>
          <Button variant="secondary" intent="destructive" onClick={() => setDeleting(true)}>{t_i18n('Delete')}</Button>
        </Box>
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
      <Tabs value={tab} panels="external">
        <TabsList className="mb-6 mt-4">
          <TabsTrigger value="overview" asChild><Link to={base}>{t_i18n('Overview')}</Link></TabsTrigger>
          <TabsTrigger value="entities" asChild><Link to={`${base}/entities`}>{t_i18n('Entities')}</Link></TabsTrigger>
          <TabsTrigger value="inbox" asChild>
            <Link to={`${base}/inbox`} style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
              {t_i18n('Inbox')}
              {ir.ir_inbox_open_count > 0 && <Badge content={ir.ir_inbox_open_count} tone="brand" accessibleText={`${ir.ir_inbox_open_count} ${t_i18n('to review')}`} />}
            </Link>
          </TabsTrigger>
          <TabsTrigger value="processing" asChild><Link to={`${base}/processing`}>{t_i18n('Processing')}</Link></TabsTrigger>
          <TabsTrigger value="configuration" asChild><Link to={`${base}/configuration`}>{t_i18n('Configuration')}</Link></TabsTrigger>
        </TabsList>
      </Tabs>
      <IrDeleteDialog
        ir={deleting ? { id: ir.id, name: ir.name } : null}
        onClose={() => setDeleting(false)}
        onDeleted={() => navigate('/dashboard/intelligence_requirements')}
      />
      <Routes>
        <Route path="/" element={<IrOverview irId={ir.id} />} />
        <Route path="/entities" element={<IrEntities irId={ir.id} />} />
        <Route path="/inbox" element={<IrInbox irId={ir.id} />} />
        <Route path="/processing" element={<IrProcessing irId={ir.id} />} />
      </Routes>
    </>
  );
};

export default IntelligenceRequirement;
