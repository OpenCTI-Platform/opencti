import React, { useState } from 'react';
import Grid from '@mui/material/Grid';
import IconButton from '@common/button/IconButton';
import { Add } from '@mui/icons-material';
import Drafts from '@components/drafts/Drafts';
import { KNOWLEDGE_KNASKIMPORT } from '../../../../../utils/hooks/useGranted';
import Security from '../../../../../utils/Security';
import useDraftContext from '../../../../../utils/hooks/useDraftContext';
import { useFormatter } from '../../../../../components/i18n';
import Card from '../../../../../components/common/card/Card';

interface DraftWorkspaceViewerProps {
  entityId: string;
}

const DraftWorkspaceViewer = ({ entityId }: DraftWorkspaceViewerProps) => {
  const { t_i18n } = useFormatter();
  const draftContext = useDraftContext();
  const [openCreate, setOpenCreate] = useState(false);

  return (
    <Grid item xs={6}>
      <Card
        padding="horizontal"
        title={t_i18n('Drafts')}
        action={draftContext ? undefined : (
          <Security needs={[KNOWLEDGE_KNASKIMPORT]}>
            <IconButton
              color="primary"
              aria-label="Add"
              onClick={() => setOpenCreate(true)}
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
      </Card>
    </Grid>
  );
};

export default DraftWorkspaceViewer;
