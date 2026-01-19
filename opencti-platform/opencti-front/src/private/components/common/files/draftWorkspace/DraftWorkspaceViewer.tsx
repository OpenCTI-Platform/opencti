import React, { useState } from 'react';
import Grid from '@mui/material/Grid';
import IconButton from '@common/button/IconButton';
import { Add } from '@mui/icons-material';
import Drafts from '@components/drafts/Drafts';
import useGranted, { hasCapabilitiesInDraft, KNOWLEDGE_KNASKIMPORT, KNOWLEDGE_KNUPDATE } from '../../../../../utils/hooks/useGranted';
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
  const canAskImport = useGranted([KNOWLEDGE_KNASKIMPORT]);
  const canCreateKnowledgeInDraft = hasCapabilitiesInDraft([KNOWLEDGE_KNUPDATE]);

  return (
    <Grid item xs={6}>
      <Card
        padding="horizontal"
        title={t_i18n('Drafts')}
        action={draftContext ? undefined : (
          <>
            {canAskImport || canCreateKnowledgeInDraft ? (
              <IconButton
                color="primary"
                aria-label="Add"
                onClick={() => setOpenCreate(true)}
                size="small"
                variant="tertiary"
              >
                <Add fontSize="small" />
              </IconButton>
            ) : (
              <span />
            )}
          </>
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
