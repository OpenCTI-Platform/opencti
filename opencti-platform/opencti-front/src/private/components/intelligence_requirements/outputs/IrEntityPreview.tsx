import React, { Suspense } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { Text } from '@filigran/design-system';
import Box from '@mui/material/Box';
import { useFormatter } from '../../../../components/i18n';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import ItemAuthor from '../../../../components/ItemAuthor';
import ItemMarkings from '../../../../components/ItemMarkings';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import StixCoreObjectLabels from '../../common/stix_core_objects/StixCoreObjectLabels';
import type { IrEntityPreviewQuery } from './__generated__/IrEntityPreviewQuery.graphql';

// Preview of the entity itself (its own information, not its relationships), to confirm it without leaving the inbox.

const previewQuery = graphql`
  query IrEntityPreviewQuery($id: String!) {
    stixCoreObject(id: $id) {
      id
      entity_type
      representative { main secondary }
      created_at
      createdBy { id name entity_type }
      objectMarking { id definition x_opencti_color }
      objectLabel { id value color }
      externalReferences(first: 5) {
        edges { node { id source_name external_id url } }
      }
      ... on StixDomainObject {
        created
        modified
        confidence
      }
    }
  }
`;

const Field = ({ label, children }: { label: string; children: React.ReactNode }) => (
  <Box>
    <Text as="div" variant="content-caption" style={{ opacity: 0.7, marginBottom: 4 }}>{label}</Text>
    {children}
  </Box>
);

const IrEntityPreviewContent = ({ entityId }: { entityId: string }) => {
  const { t_i18n, fsd } = useFormatter();
  const { stixCoreObject: entity } = useLazyLoadQuery<IrEntityPreviewQuery>(previewQuery, { id: entityId }, { fetchPolicy: 'store-and-network' });
  if (!entity) {
    return <Text as="div" variant="content-caption">{t_i18n('This entity no longer exists or is not accessible.')}</Text>;
  }
  const references = (entity.externalReferences?.edges ?? []).map((e) => e.node);
  const created = entity.created ?? entity.created_at;
  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
      <Field label={t_i18n('Description')}>
        {entity.representative.secondary
          ? <ExpandableMarkdown source={entity.representative.secondary} limit={400} />
          : <Text as="span" variant="content-caption">-</Text>}
      </Field>
      <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 2 }}>
        <Field label={t_i18n('Author')}><ItemAuthor createdBy={entity.createdBy} /></Field>
        <Field label={t_i18n('Marking')}><ItemMarkings markingDefinitions={entity.objectMarking} limit={3} /></Field>
        <Field label={t_i18n('Labels')}><StixCoreObjectLabels labels={entity.objectLabel} /></Field>
        <Field label={t_i18n('Confidence')}>
          <Text as="span" variant="content-compact">{entity.confidence != null ? String(entity.confidence) : '-'}</Text>
        </Field>
        <Field label={t_i18n('Created')}><Text as="span" variant="content-compact">{created ? fsd(created) : '-'}</Text></Field>
        <Field label={t_i18n('Modified')}><Text as="span" variant="content-compact">{entity.modified ? fsd(entity.modified) : '-'}</Text></Field>
      </Box>
      <Field label={t_i18n('External references')}>
        {references.length === 0 && <Text as="span" variant="content-caption">-</Text>}
        {references.map((r) => (
          <Text key={r.id} as="div" variant="content-caption">
            {r.url
              ? <a href={r.url} target="_blank" rel="noopener noreferrer">{`${r.source_name}${r.external_id ? ` · ${r.external_id}` : ''}`}</a>
              : `${r.source_name}${r.external_id ? ` · ${r.external_id}` : ''}`}
          </Text>
        ))}
      </Field>
    </Box>
  );
};

const IrEntityPreview = ({ entityId }: { entityId: string }) => (
  <Box sx={{ border: '1px solid', borderColor: 'divider', borderRadius: 1, p: 2 }}>
    <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      <IrEntityPreviewContent entityId={entityId} />
    </Suspense>
  </Box>
);

export default IrEntityPreview;
