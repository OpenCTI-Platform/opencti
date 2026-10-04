/*
Copyright (c) 2021-2025 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import React, { useState } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { Link } from 'react-router';
import Box from '@mui/material/Box';
import Stack from '@mui/material/Stack';
import Typography from '@mui/material/Typography';
import { Chip } from '@filigran/design-system';
import Button from '@common/button/Button';
import ItemIcon from '../../../components/ItemIcon';
import { useFormatter } from '../../../components/i18n';
import { draftChangeOperation, type DraftChange } from './investigationRunDraftChanges';
import { InvestigationRunDraftPreviewQuery } from './__generated__/InvestigationRunDraftPreviewQuery.graphql';

// Rows loaded for the preview; the draft page shows the full diff beyond them.
const PREVIEW_LOAD = 50;
const PREVIEW_VISIBLE = 5;

const investigationRunDraftPreviewQuery = graphql`
  query InvestigationRunDraftPreviewQuery($draftId: String!, $first: Int!) {
    draftWorkspaceEntities(draftId: $draftId, first: $first) {
      edges {
        node {
          id
          entity_type
          representative {
            main
          }
          draftVersion {
            draft_operation
          }
        }
      }
    }
    draftWorkspaceRelationships(draftId: $draftId, first: $first) {
      edges {
        node {
          id
          relationship_type
          draftVersion {
            draft_operation
          }
          from {
            ... on StixCoreObject {
              representative {
                main
              }
            }
          }
          to {
            ... on StixCoreObject {
              representative {
                main
              }
            }
          }
        }
      }
    }
  }
`;

const OPERATION_LABELS: Record<DraftChange['operation'], string> = {
  create: 'Create',
  update: 'Update',
  delete: 'Delete',
};

const ChangeRow = ({ change }: { change: DraftChange }) => {
  const { t_i18n } = useFormatter();
  const isRelationship = change.kind === 'relationship';
  const label = isRelationship
    ? t_i18n('{from} {relationship} {to}', {
        values: {
          from: change.fromName ?? t_i18n('a restricted entity'),
          relationship: t_i18n(`relationship_${change.type}`),
          to: change.toName ?? t_i18n('a restricted entity'),
        },
      })
    : change.name;
  return (
    <Stack component="li" direction="row" spacing={1.5} alignItems="center" sx={{ paddingY: 0.5, minWidth: 0 }} data-testid="investigation-draft-change">
      <ItemIcon type={isRelationship ? 'Relationship' : change.type} size="small" />
      <Typography variant="body2" sx={{ minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={label}>
        {label}
      </Typography>
      <Typography variant="caption" color="text.secondary" sx={{ flexShrink: 0 }}>
        {isRelationship ? t_i18n('Relationship') : t_i18n(`entity_${change.type}`)}
      </Typography>
      <Box sx={{ flex: 1 }} />
      <Chip label={t_i18n(OPERATION_LABELS[change.operation])} severity={change.operation === 'delete' ? 'high' : 'neutral'} size="sm" />
    </Stack>
  );
};

interface InvestigationRunDraftPreviewProps {
  draftId: string;
  total: number;
}

/** The first changes the investigation draft writes to the case, each with its operation, and the way to the full diff. */
const InvestigationRunDraftPreview = ({ draftId, total }: InvestigationRunDraftPreviewProps) => {
  const { t_i18n, n } = useFormatter();
  const [showAll, setShowAll] = useState(false);
  const data = useLazyLoadQuery<InvestigationRunDraftPreviewQuery>(
    investigationRunDraftPreviewQuery,
    { draftId, first: PREVIEW_LOAD },
    { fetchPolicy: 'store-and-network' },
  );
  const entities = (data.draftWorkspaceEntities?.edges ?? []).flatMap((edge) => (edge?.node ? [edge.node] : []));
  const relationships = (data.draftWorkspaceRelationships?.edges ?? []).flatMap((edge) => (edge?.node ? [edge.node] : []));
  const changes: DraftChange[] = [
    ...entities.map((node): DraftChange => ({
      kind: 'entity',
      id: node.id,
      type: node.entity_type,
      name: node.representative.main,
      operation: draftChangeOperation(node.draftVersion?.draft_operation),
    })),
    ...relationships.map((node): DraftChange => ({
      kind: 'relationship',
      id: node.id,
      type: node.relationship_type,
      name: node.relationship_type,
      fromName: node.from?.representative?.main ?? null,
      toName: node.to?.representative?.main ?? null,
      operation: draftChangeOperation(node.draftVersion?.draft_operation),
    })),
  ];
  if (changes.length === 0) {
    return <Typography variant="body2" color="text.secondary">{t_i18n('The draft holds no change yet.')}</Typography>;
  }
  const visible = showAll ? changes : changes.slice(0, PREVIEW_VISIBLE);
  const count = Math.max(total, changes.length);
  return (
    <Stack spacing={1} data-testid="investigation-draft-preview">
      <Box component="ul" sx={{ listStyle: 'none', margin: 0, padding: 0 }} aria-label={t_i18n('Changes of the draft')}>
        {visible.map((change) => <ChangeRow key={change.id} change={change} />)}
      </Box>
      <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
        {changes.length > PREVIEW_VISIBLE && (
          <Button size="small" variant="tertiary" onClick={() => setShowAll(!showAll)} aria-expanded={showAll}>
            {showAll ? t_i18n('Show less') : t_i18n('Show all {count} changes', { values: { count: n(changes.length) } })}
          </Button>
        )}
        <Button size="small" variant="tertiary" component={Link} to={`/dashboard/data/import/draft/${draftId}`}>
          {count > changes.length ? t_i18n('Open the draft to see all {count} changes', { values: { count: n(count) } }) : t_i18n('Open the draft')}
        </Button>
      </Stack>
    </Stack>
  );
};

export default InvestigationRunDraftPreview;
