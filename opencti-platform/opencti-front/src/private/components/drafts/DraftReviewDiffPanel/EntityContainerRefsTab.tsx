import React, { FunctionComponent, Suspense } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import Typography from '@mui/material/Typography';
import Box from '@mui/material/Box';
import Chip from '@mui/material/Chip';
import IconButton from '@mui/material/IconButton';
import LaunchIcon from '@mui/icons-material/Launch';
import { Link } from 'react-router-dom';
import { useFormatter } from '../../../../components/i18n';
import { resolveLink } from '../../../../utils/Entity';
import { EntityContainerRefsTabQuery } from './__generated__/EntityContainerRefsTabQuery.graphql';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader from '../../../../components/Loader';

const draftReviewDiffPanelEntityContainerRefsQuery = graphql`
  query EntityContainerRefsTabQuery($draftId: String!, $entityId: String!) {
    draftWorkspaceEntityContainerRefs(draftId: $draftId, entityId: $entityId) {
      container_id
      container_type
      container_name
      draft_operation
    }
  }
`;

interface EntityContainerRefsTabComponentProps {
  queryRef: PreloadedQuery<EntityContainerRefsTabQuery>;
}

const EntityContainerRefsTabComponent: FunctionComponent<EntityContainerRefsTabComponentProps> = ({ queryRef }) => {
  const { t_i18n } = useFormatter();

  const data = usePreloadedQuery<EntityContainerRefsTabQuery>(
    draftReviewDiffPanelEntityContainerRefsQuery,
    queryRef,
  );

  const refs = data.draftWorkspaceEntityContainerRefs ?? [];

  if (refs.length === 0) {
    return (
      <Typography variant="body2" sx={{ color: 'text.secondary', mt: 2 }}>
        {t_i18n('No containers added or removed for this entity')}
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
          {t_i18n('Type')}
        </Typography>
        <Typography sx={{ flex: 3, fontSize: 12, fontWeight: 600, color: 'text.secondary' }}>
          {t_i18n('Container')}
        </Typography>
      </Box>
      <Box sx={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
        {refs.map((ref) => {
          const isAdd = ref.draft_operation === 'add';
          const containerBaseLink = resolveLink(ref.container_type);
          const containerLink = containerBaseLink ? `${containerBaseLink}/${ref.container_id}` : undefined;
          return (
            <Box
              key={ref.container_id}
              sx={{ display: 'flex', flexDirection: 'row', alignItems: 'center' }}
            >
              <Box sx={{ width: 120 }}>
                <Chip
                  label={isAdd ? t_i18n('Added to') : t_i18n('Removed from')}
                  color={isAdd ? 'success' : 'error'}
                  size="small"
                  sx={{ borderRadius: '4px', height: 24, fontSize: 12, fontWeight: 600 }}
                />
              </Box>
              <Box sx={{ flex: 1, pr: 2 }}>
                <Typography sx={{ fontSize: 14, color: 'text.primary', wordBreak: 'break-word' }}>
                  {t_i18n(`entity_${ref.container_type}`)}
                </Typography>
              </Box>
              <Box sx={{ flex: 3, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <Typography sx={{ fontSize: 14, color: 'text.primary', wordBreak: 'break-word' }}>
                  {ref.container_name || ref.container_id}
                </Typography>
                {containerLink && (
                  <IconButton
                    component={Link}
                    to={containerLink}
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

interface EntityContainerRefsTabProps {
  draftId: string;
  entityId: string;
}

const EntityContainerRefsTab: FunctionComponent<EntityContainerRefsTabProps> = ({ draftId, entityId }) => {
  const queryRef = useQueryLoading<EntityContainerRefsTabQuery>(
    draftReviewDiffPanelEntityContainerRefsQuery,
    { draftId, entityId },
  );
  return (
    <Suspense fallback={<Loader />}>
      {queryRef && <EntityContainerRefsTabComponent queryRef={queryRef} />}
    </Suspense>
  );
};

export default EntityContainerRefsTab;
