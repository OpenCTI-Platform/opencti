import React, { FunctionComponent, Suspense } from 'react';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import Loader from '../../../../components/Loader';
import { useFormatter } from '../../../../components/i18n';
import { ErrorBoundary } from '../../Error';
import { DraftEntitySelection } from '../DraftReviewEntityList';
import DraftReviewDiffPanelContent from './DraftReviewDiffPanelContent';

interface DraftReviewDiffPanelProps {
  draftId: string;
  entity: DraftEntitySelection | null;
}

const DraftReviewDiffPanel: FunctionComponent<DraftReviewDiffPanelProps> = ({
  draftId,
  entity,
}) => {
  const { t_i18n } = useFormatter();

  if (!entity) {
    return (
      <Box
        sx={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          height: '100%',
          color: 'text.secondary',
        }}
      >
        <Typography variant="body2">
          {t_i18n('Select an entity on the left to see its changes')}
        </Typography>
      </Box>
    );
  }

  return (
    <ErrorBoundary>
      <Suspense fallback={<Loader />}>
        <DraftReviewDiffPanelContent draftId={draftId} entity={entity} />
      </Suspense>
    </ErrorBoundary>
  );
};

export default DraftReviewDiffPanel;
