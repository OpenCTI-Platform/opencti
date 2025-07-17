import React, { useState } from 'react';
import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import { Add } from '@mui/icons-material';
import Paper from '@mui/material/Paper';
import Drafts from '@components/drafts/Drafts';
import { useTheme } from '@mui/styles';
import { graphql, loadQuery, usePreloadedQuery } from 'react-relay';
import { DraftWorkspaceViewerQuery } from '@components/common/files/draftWorkspace/__generated__/DraftWorkspaceViewerQuery.graphql';
import { KNOWLEDGE_KNASKIMPORT } from '../../../../../utils/hooks/useGranted';
import Security from '../../../../../utils/Security';
import useDraftContext from '../../../../../utils/hooks/useDraftContext';
import { useFormatter } from '../../../../../components/i18n';
import { environment } from '../../../../../relay/environment';
import type { Theme } from '../../../../../components/Theme';

const draftWorkspaceQuery = graphql`
  query DraftWorkspaceViewerQuery {
    draftWorkspaces {
      edges {
        node {
          id
          entity_id
          name
        }
      }
    }
  }
`;

const queryRef = loadQuery<DraftWorkspaceViewerQuery>(
  environment,
  draftWorkspaceQuery,
  {},
);

const DraftWorkspaceViewer = ({ entityId }: { entityId: string }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const draftContext = useDraftContext();
  const [openCreate, setOpenCreate] = useState(false);

  const data = usePreloadedQuery<DraftWorkspaceViewerQuery>(
    draftWorkspaceQuery,
    queryRef,
  );

  const draftWorkspaces = data?.draftWorkspaces?.edges
    .map((n) => n.node.entity_id);

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
          {draftWorkspaces && draftWorkspaces.includes(entityId) ? (
            <Drafts
              entityId={entityId}
              setOpenCreate={() => setOpenCreate(false)}
              openCreate={openCreate}
            />
          ) : (
            <div style={{ display: 'table', height: '100%', width: '100%' }}>
              <span
                style={{
                  display: 'table-cell',
                  verticalAlign: 'middle',
                  textAlign: 'center',
                }}
              >
                {t_i18n('No draft for the moment')}
              </span>
            </div>
          )}
        </Paper>
      </div>
    </Grid>
  );
};

export default DraftWorkspaceViewer;
