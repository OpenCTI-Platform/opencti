import React, { FunctionComponent, Suspense } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import Typography from '@mui/material/Typography';
import Box from '@mui/material/Box';
import Chip from '@mui/material/Chip';
import IconButton from '@mui/material/IconButton';
import LaunchIcon from '@mui/icons-material/Launch';
import { Link } from 'react-router-dom';
import { useFormatter } from '../../../../components/i18n';
import { useComputeLink } from '../../../../utils/hooks/useAppData';
import { EntityRelationsTabQuery } from './__generated__/EntityRelationsTabQuery.graphql';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader from '../../../../components/Loader';
import useEntityTranslation from '../../../../utils/hooks/useEntityTranslation';

const draftReviewDiffPanelEntityRelationsQuery = graphql`
  query EntityRelationsTabQuery($draftId: String!, $entityId: String!) {
    draftWorkspaceEntityRelations(draftId: $draftId, entityId: $entityId) {
      relation_id
      relationship_type
      from_id
      from_type
      from_name
      to_id
      to_type
      to_name
      draft_operation
    }
  }
`;

interface EntityRelationsTabComponentProps {
  queryRef: PreloadedQuery<EntityRelationsTabQuery>;
}

const EntityRelationsTabComponent: FunctionComponent<EntityRelationsTabComponentProps> = ({ queryRef }) => {
  const { t_i18n } = useFormatter();
  const computeLink = useComputeLink();
  const { translateEntityType } = useEntityTranslation();

  const data = usePreloadedQuery<EntityRelationsTabQuery>(
    draftReviewDiffPanelEntityRelationsQuery,
    queryRef,
  );

  const relations = data.draftWorkspaceEntityRelations ?? [];

  if (relations.length === 0) {
    return (
      <Typography variant="body2" sx={{ color: 'text.secondary', mt: 2 }}>
        {t_i18n('No relations created or deleted for this entity')}
      </Typography>
    );
  }

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', backgroundColor: 'background.paper', borderRadius: '4px', p: '16px' }}>
      <Box sx={{ display: 'flex', flexDirection: 'row', alignItems: 'center', mb: 2 }}>
        <Typography sx={{ width: 120, fontSize: 12, fontWeight: 600, color: 'text.secondary' }}>
          {t_i18n('Action')}
        </Typography>
        <Typography sx={{ flex: 1, fontSize: 12, fontWeight: 600, color: 'text.secondary' }}>
          {t_i18n('Relation type')}
        </Typography>
        <Typography sx={{ flex: 3, fontSize: 12, fontWeight: 600, color: 'text.secondary' }}>
          {t_i18n('From → To')}
        </Typography>
      </Box>
      <Box sx={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
        {relations.map((rel) => {
          const isCreate = rel.draft_operation === 'create';
          const relationLink = computeLink({
            id: rel.relation_id,
            entity_type: rel.relationship_type,
            relationship_type: rel.relationship_type,
            from: rel.from_id && rel.from_type ? { id: rel.from_id, entity_type: rel.from_type } : undefined,
            to: rel.to_id && rel.to_type ? { id: rel.to_id, entity_type: rel.to_type } : undefined,
          });
          return (
            <Box
              key={rel.relation_id}
              sx={{ display: 'flex', flexDirection: 'row', alignItems: 'center' }}
            >
              <Box sx={{ width: 120 }}>
                <Chip
                  label={isCreate ? t_i18n('Created') : t_i18n('Deleted')}
                  color={isCreate ? 'success' : 'error'}
                  size="small"
                  sx={{ borderRadius: '4px', height: 24, fontSize: 12, fontWeight: 600 }}
                />
              </Box>
              <Box sx={{ flex: 1, pr: 2 }}>
                <Typography sx={{ fontSize: 14, color: 'text.primary', wordBreak: 'break-word' }}>
                  {translateEntityType(rel.relationship_type)}
                </Typography>
              </Box>
              <Box sx={{ flex: 3, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <Typography sx={{ fontSize: 14, color: 'text.primary', wordBreak: 'break-word' }}>
                  {rel.from_name || rel.from_id}
                  <Box component="span" sx={{ mx: 1, color: 'text.secondary' }}>→</Box>
                  {rel.to_name || rel.to_id}
                </Typography>
                {relationLink && (
                  <IconButton
                    aria-label={t_i18n('Open link in new tab')}
                    component={Link}
                    to={relationLink}
                    target="_blank"
                    rel="noopener noreferrer"
                    size="small"
                    sx={{ width: 26, height: 26, borderRadius: '4px', color: 'primary.main', backgroundColor: 'action.hover', flexShrink: 0 }}
                  >
                    <LaunchIcon sx={{ fontSize: 18 }} />
                  </IconButton>
                )}
              </Box>
            </Box>
          );
        })}
      </Box>
    </Box>
  );
};

interface EntityRelationsTabProps {
  draftId: string;
  entityId: string;
}

const EntityRelationsTab: FunctionComponent<EntityRelationsTabProps> = ({ draftId, entityId }) => {
  const queryRef = useQueryLoading<EntityRelationsTabQuery>(
    draftReviewDiffPanelEntityRelationsQuery,
    { draftId, entityId },
  );
  return (
    <Suspense fallback={<Loader />}>
      {queryRef && <EntityRelationsTabComponent queryRef={queryRef} />}
    </Suspense>
  );
};

export default EntityRelationsTab;
