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
import useEntityTranslation from '../../../../utils/hooks/useEntityTranslation';
import { ContainerObjectsTabQuery } from './__generated__/ContainerObjectsTabQuery.graphql';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader from '../../../../components/Loader';

const draftReviewDiffPanelContainerObjectsQuery = graphql`
  query ContainerObjectsTabQuery($draftId: String!, $containerId: String!) {
    draftWorkspaceContainerObjects(draftId: $draftId, containerId: $containerId) {
      entity_id
      entity_type
      representative_main
      draft_operation
    }
  }
`;

interface ContainerObjectsTabComponentProps {
  queryRef: PreloadedQuery<ContainerObjectsTabQuery>;
}

const ContainerObjectsTabComponent: FunctionComponent<ContainerObjectsTabComponentProps> = ({ queryRef }) => {
  const { t_i18n } = useFormatter();
  const computeLink = useComputeLink();
  const { translateEntityType } = useEntityTranslation();

  const data = usePreloadedQuery<ContainerObjectsTabQuery>(
    draftReviewDiffPanelContainerObjectsQuery,
    queryRef,
  );

  const objects = data.draftWorkspaceContainerObjects ?? [];

  if (objects.length === 0) {
    return (
      <Typography variant="body2" sx={{ color: 'text.secondary', mt: 2 }}>
        {t_i18n('No objects added or removed from this container')}
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
          {t_i18n('Representation')}
        </Typography>
      </Box>
      <Box sx={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
        {objects.map((obj) => {
          const isAdd = obj.draft_operation === 'add';
          const objectLink = computeLink({ id: obj.entity_id, entity_type: obj.entity_type });
          return (
            <Box
              key={obj.entity_id}
              sx={{ display: 'flex', flexDirection: 'row', alignItems: 'center' }}
            >
              <Box sx={{ width: 120 }}>
                <Chip
                  label={isAdd ? t_i18n('Added') : t_i18n('Removed')}
                  color={isAdd ? 'success' : 'error'}
                  size="small"
                  sx={{ borderRadius: '4px', height: 24, fontSize: 12, fontWeight: 600 }}
                />
              </Box>
              <Box sx={{ flex: 1, pr: 2 }}>
                <Typography sx={{ fontSize: 14, color: 'text.primary', wordBreak: 'break-word' }}>
                  {translateEntityType(obj.entity_type)}
                </Typography>
              </Box>
              <Box sx={{ flex: 3, display: 'flex', alignItems: 'center', justifyContent: 'space-between', minWidth: 0 }}>
                <Typography sx={{ fontSize: 14, color: 'text.primary', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', mr: 1 }}>
                  {obj.representative_main ?? obj.entity_id}
                </Typography>
                {objectLink && (
                  <IconButton
                    component={Link}
                    to={objectLink}
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

interface ContainerObjectsTabProps {
  draftId: string;
  containerId: string;
}

const ContainerObjectsTab: FunctionComponent<ContainerObjectsTabProps> = ({ draftId, containerId }) => {
  const queryRef = useQueryLoading<ContainerObjectsTabQuery>(
    draftReviewDiffPanelContainerObjectsQuery,
    { draftId, containerId },
  );
  return (
    <Suspense fallback={<Loader />}>
      {queryRef && <ContainerObjectsTabComponent queryRef={queryRef} />}
    </Suspense>
  );
};

export default ContainerObjectsTab;
