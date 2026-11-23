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
  // Only the fields that hold a value; the empty ones are named on one quiet line, never a column of dashes
  const fields: { label: string; set: boolean; node: React.ReactNode }[] = [
    { label: 'Author', set: !!entity.createdBy, node: <ItemAuthor createdBy={entity.createdBy} /> },
    { label: 'Marking', set: (entity.objectMarking ?? []).length > 0, node: <ItemMarkings markingDefinitions={entity.objectMarking} limit={3} /> },
    { label: 'Labels', set: (entity.objectLabel ?? []).length > 0, node: <StixCoreObjectLabels labels={entity.objectLabel} /> },
    { label: 'Confidence', set: entity.confidence != null, node: <Text as="span" variant="content-compact">{String(entity.confidence)}</Text> },
    { label: 'Created', set: !!created, node: <Text as="span" variant="content-compact">{created ? fsd(created) : null}</Text> },
    { label: 'Modified', set: !!entity.modified, node: <Text as="span" variant="content-compact">{entity.modified ? fsd(entity.modified) : null}</Text> },
  ];
  const shown = fields.filter((f) => f.set);
  const empty = [
    ...(entity.representative.secondary ? [] : ['Description']),
    ...fields.filter((f) => !f.set).map((f) => f.label),
    ...(references.length > 0 ? [] : ['External references']),
  ].map((label) => t_i18n(label));
  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
      {entity.representative.secondary && (
        <Field label={t_i18n('Description')}>
          <ExpandableMarkdown source={entity.representative.secondary} limit={400} />
        </Field>
      )}
      {shown.length > 0 && (
        <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 2 }}>
          {shown.map((f) => <Field key={f.label} label={t_i18n(f.label)}>{f.node}</Field>)}
        </Box>
      )}
      {references.length > 0 && (
        <Field label={t_i18n('External references')}>
          {references.map((r) => (
            <Text key={r.id} as="div" variant="content-caption">
              {r.url
                ? <a href={r.url} target="_blank" rel="noopener noreferrer">{`${r.source_name}${r.external_id ? ` · ${r.external_id}` : ''}`}</a>
                : `${r.source_name}${r.external_id ? ` · ${r.external_id}` : ''}`}
            </Text>
          ))}
        </Field>
      )}
      {empty.length > 0 && (
        <Text as="div" variant="content-caption" style={{ opacity: 0.7 }}>
          {`${t_i18n('{count, plural, one {# field not set} other {# fields not set}}', { values: { count: empty.length } })}: ${empty.join(', ')}`}
        </Text>
      )}
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
