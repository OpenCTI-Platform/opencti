import React, { useState } from 'react';
import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import { Add } from '@mui/icons-material';
import Paper from '@mui/material/Paper';
import Drafts from '@components/drafts/Drafts';
import { useTheme } from '@mui/styles';
import { KNOWLEDGE_KNASKIMPORT } from '../../../../../utils/hooks/useGranted';
import Security from '../../../../../utils/Security';
import useDraftContext from '../../../../../utils/hooks/useDraftContext';
import { useFormatter } from '../../../../../components/i18n';
import type { Theme } from '../../../../../components/Theme';

const DraftWorkspaceViewer = ({ entityId }: { entityId: string }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const draftContext = useDraftContext();
  const [openCreate, setOpenCreate] = useState(false);
  const dataTableEmptyState = (
    <div style={{
      display: 'table',
      height: '100%',
      width: '100%',
      textAlign: 'center',
    }}
    >
      {t_i18n('No draft for the moment')}
    </div>
  );

  return (
    <Grid item xs={6}>
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true} style={{ float: 'left', marginBottom: theme.spacing(2) }}>
          {t_i18n('Drafts')}
        </Typography>
        {!draftContext && (
          <Security needs={[KNOWLEDGE_KNASKIMPORT]} placeholder={<div style={{ height: 28 }}/>}>
            <IconButton
              color="primary"
              aria-label="Add"
              onClick={() => setOpenCreate(true)}
              style={{ marginTop: -15 }}
              size="large"
            >
              <Add fontSize="small" />
            </IconButton>
          </Security>
        )}
        <div className="clearfix" />
        <Paper
          style={{
            padding: '10px 15px 10px 15px',
            marginTop: -2,
            borderRadius: 4,
          }}
          className={'paper-for-grid'} variant="outlined"
        >
          <Drafts
            entityId={entityId}
            setOpenCreate={() => setOpenCreate(false)}
            openCreate={openCreate}
            emptyState={dataTableEmptyState}
          />
        </Paper>
      </div>
    </Grid>
  );
};

export default DraftWorkspaceViewer;
