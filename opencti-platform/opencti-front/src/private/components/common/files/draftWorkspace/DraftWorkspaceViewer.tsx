import React, { useState } from 'react';
import Grid from '@mui/material/Grid';
import IconButton from '@common/button/IconButton';
import { Add } from '@mui/icons-material';
import Drafts from '@components/drafts/Drafts';
import { KNOWLEDGE_KNASKIMPORT } from '../../../../../utils/hooks/useGranted';
import Security from '../../../../../utils/Security';
import useDraftContext from '../../../../../utils/hooks/useDraftContext';
import { useFormatter } from '../../../../../components/i18n';
import Paper from '../../../../../components/Paper';

interface DraftWorkspaceViewerProps {
  entityId: string;
}

const DraftWorkspaceViewer = ({ entityId }: DraftWorkspaceViewerProps) => {
  const { t_i18n } = useFormatter();
  const draftContext = useDraftContext();
  const [openCreate, setOpenCreate] = useState(false);

  return (
    <Grid item xs={6}>
      <Paper
        title={t_i18n('Drafts')}
        actions={draftContext ? undefined : (
          <Security needs={[KNOWLEDGE_KNASKIMPORT]} placeholder={<div style={{ height: 28 }} />}>
            <IconButton
              color="primary"
              aria-label="Add"
              onClick={() => setOpenCreate(true)}
              sx={{ marginTop: -0.8 }}
              size="small"
              variant="tertiary"
            >
              <Add fontSize="small" />
            </IconButton>
          </Security>
        )}
      >
        <Drafts
          entityId={entityId}
          setOpenCreate={() => setOpenCreate(false)}
          openCreate={openCreate}
          emptyStateMessage={t_i18n('No draft for the moment')}
        />
      </Paper>
    </Grid>
  );
};

export default DraftWorkspaceViewer;
