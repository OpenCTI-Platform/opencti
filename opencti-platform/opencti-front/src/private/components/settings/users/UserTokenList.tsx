import React, { useState } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { RecordSourceSelectorProxy, RecordProxy } from 'relay-runtime';
import {
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  IconButton,
  Tooltip,
  Dialog,
  DialogContent,
  DialogContentText,
  DialogActions,
  Button,
  DialogTitle,
} from '@mui/material';
import { Delete, Add } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';
import UserTokenCreationDrawer from './UserTokenCreationDrawer';
import { UserTokenList_node$data } from './__generated__/UserTokenList_node.graphql';

const useStyles = makeStyles<Theme>((theme) => ({
  container: {
    marginTop: 0,
  },
  table: {
    minWidth: 650,
  },
  empty: {
    textAlign: 'center',
    padding: 20,
    color: theme.palette.text?.secondary,
  },
  warning: {
    color: '#faa05a',
    fontWeight: 'bold',
  },
  error: {
    color: '#f44336',
    fontWeight: 'bold',
  },
}));

const userTokenListRevokeMutation = graphql`
  mutation UserTokenListAdminRevokeMutation($userId: ID!, $id: ID!) {
    userAdminTokenRevoke(userId: $userId, id: $id)
  }
`;

interface UserTokenListProps {
  node: UserTokenList_node$data;
}

export const UserTokenList: React.FC<UserTokenListProps> = ({ node }) => {
  const classes = useStyles();
  const { t_i18n, nsdt } = useFormatter();
  const [deletingToken, setDeletingToken] = useState<{ id: string; name: string } | null>(null);

  const [creationOpen, setCreationOpen] = useState(false);

  const tokens = node.api_tokens || [];
  const now = new Date();

  const getExpirationStatus = (expiresAt: string | null) => {
    if (!expiresAt) return null;
    const expirationDate = new Date(expiresAt);
    const diffTime = expirationDate.getTime() - now.getTime();
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));

    if (diffDays < 0) {
      return <span className={classes.error}>{t_i18n('Expired')}</span>;
    }
    if (diffDays <= 7) {
      return <span className={classes.warning}>{t_i18n('Expires soon')}</span>;
    }
    return null;
  };

  const handleOpenDelete = (token: { id: string; name: string }) => {
    setDeletingToken(token);
  };

  const handleCloseDelete = () => {
    setDeletingToken(null);
  };

  const submitDelete = () => {
    // ... same logic
    if (!deletingToken) return;
    commitMutation({
      mutation: userTokenListRevokeMutation,
      variables: {
        userId: node.id,
        id: deletingToken.id,
      },
      updater: (store: RecordSourceSelectorProxy) => {
        const userProxy = store.get(node.id);
        if (!userProxy) return;
        const currentTokens = userProxy.getLinkedRecords('api_tokens');
        if (currentTokens) {
          userProxy.setLinkedRecords(
            currentTokens.filter((t: RecordProxy) => t.getDataID() !== deletingToken.id),
            'api_tokens',
          );
        }
      },
      optimisticUpdater: undefined,
      optimisticResponse: undefined,
      onCompleted: () => {
        MESSAGING$.notifySuccess(t_i18n('Token revoked successfully'));
        handleCloseDelete();
      },
      onError: (error: Error) => {
        MESSAGING$.notifyError(error);
        handleCloseDelete();
      },
      setSubmitting: undefined,
    });
  };

  return (
    <div className={classes.container}>
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 10 }}>
        <Button
          variant="contained"
          color="primary"
          size="small"
          startIcon={<Add />}
          onClick={() => setCreationOpen(true)}
          aria-label="generate-token"
        >
          {t_i18n('Generate')}
        </Button>
      </div>
      {tokens.length === 0 ? (
        <Paper variant="outlined" className={classes.container}>
          <div className={classes.empty}>
            {t_i18n('No tokens found.')}
          </div>
        </Paper>
      ) : (
        <TableContainer component={Paper} variant="outlined">
          <Table className={classes.table} size="small" aria-label="token list">
            <TableHead>
              <TableRow>
                <TableCell>{t_i18n('Name')}</TableCell>
                <TableCell>{t_i18n('Last Used')}</TableCell>
                <TableCell>{t_i18n('Expires At')}</TableCell>
                <TableCell align="right">{t_i18n('Actions')}</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {tokens.map((token) => (
                <TableRow key={token.id}>
                  <TableCell component="th" scope="row">
                    {token.name || '-'}
                  </TableCell>
                  <TableCell>{token.last_used_at ? nsdt(token.last_used_at) : t_i18n('Never used')}</TableCell>
                  <TableCell>
                    {token.expires_at ? nsdt(token.expires_at) : t_i18n('Unlimited')}
                    {' '}
                    {getExpirationStatus(token.expires_at)}
                  </TableCell>
                  <TableCell align="right">
                    <Tooltip title={t_i18n('Revoke')}>
                      <IconButton
                        aria-label="revoke"
                        color="primary"
                        onClick={() => handleOpenDelete({ id: token.id, name: token.name || '' })}
                        size="small"
                      >
                        <Delete fontSize="small" />
                      </IconButton>
                    </Tooltip>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}
      <Dialog
        open={deletingToken !== null}
        onClose={handleCloseDelete}
        aria-labelledby="alert-dialog-title"
        aria-describedby="alert-dialog-description"
      >
        <DialogTitle id="alert-dialog-title">{t_i18n('Revoke API Token')}</DialogTitle>
        <DialogContent>
          <DialogContentText id="alert-dialog-description">
            {t_i18n('Do you want to revoke the token')} <strong>{deletingToken?.name}</strong>?
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseDelete}>
            {t_i18n('Cancel')}
          </Button>
          <Button onClick={submitDelete} color="error" autoFocus>
            {t_i18n('Revoke')}
          </Button>
        </DialogActions>
      </Dialog>
      <UserTokenCreationDrawer
        userId={node.id}
        open={creationOpen}
        onClose={() => setCreationOpen(false)}
      />
    </div>
  );
};

export default createFragmentContainer(UserTokenList, {
  node: graphql`
    fragment UserTokenList_node on User {
      id
      api_tokens {
        id
        name
        created_at
        expires_at
        last_used_at
      }
    }
  `,
});
