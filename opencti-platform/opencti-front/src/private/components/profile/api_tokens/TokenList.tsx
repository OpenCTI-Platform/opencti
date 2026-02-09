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
  DialogTitle,
  Alert,
} from '@mui/material';
import Button from '@common/button/Button';
import { Delete } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import useGranted, { APIACCESS_USETOKEN } from '../../../../utils/hooks/useGranted';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';
import { TokenList_node$data } from './__generated__/TokenList_node.graphql';

const useStyles = makeStyles<Theme>((theme) => ({
  container: {
    marginTop: 20,
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
    color: '#faa05a', // Orange/Yellow manually or use theme warning if available
    fontWeight: 'bold',
  },
  error: {
    color: '#f44336',
    fontWeight: 'bold',
  },
}));

const tokenListRevokeMutation = graphql`
  mutation TokenListRevokeMutation($id: ID!) {
    userTokenRevoke(id: $id)
  }
`;

interface TokenListProps {
  node: TokenList_node$data;
}

export const TokenListBase: React.FC<TokenListProps> = ({ node }) => {
  const classes = useStyles();
  const { t_i18n, nsdt } = useFormatter();
  const [deletingToken, setDeletingToken] = useState<{ id: string; name: string } | null>(null);
  const hasAccessTokenCapability = useGranted([APIACCESS_USETOKEN]);

  if (!hasAccessTokenCapability) {
    return (
      <Alert severity="warning" variant="outlined">
        {t_i18n('You do not have the right to use API tokens.')}
      </Alert>
    );
  }

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
    if (!deletingToken) return;
    commitMutation({
      mutation: tokenListRevokeMutation,
      variables: {
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

  if (tokens.length === 0) {
    return (
      <Paper variant="outlined" className={classes.container}>
        <div className={classes.empty}>
          {t_i18n('No tokens found. Click "Generate Token" to create one.')}
        </div>
      </Paper>
    );
  }

  return (
    <div className={classes.container}>
      <TableContainer component={Paper} variant="outlined">
        <Table className={classes.table} size="small" aria-label="token list">
          <TableHead>
            <TableRow>
              <TableCell>{t_i18n('Name')}</TableCell>
              <TableCell>{t_i18n('Token')}</TableCell>
              <TableCell>{t_i18n('Last Used')}</TableCell>
              <TableCell>{t_i18n('Expires At')}</TableCell>
              <TableCell align="right">{t_i18n('Actions')}</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {tokens.map((token) => (
              <TableRow key={token.id}>
                <TableCell component="th" scope="row">
                  {token.name}
                </TableCell>
                <TableCell>
                  {token.masked_token}
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
          <Button
            variant="secondary"
            onClick={handleCloseDelete}
          >
            {t_i18n('Cancel')}
          </Button>
          <Button
            intent="destructive"
            onClick={submitDelete}
            autoFocus
          >
            {t_i18n('Revoke')}
          </Button>
        </DialogActions>
      </Dialog>
    </div>
  );
};

export default createFragmentContainer(TokenListBase, {
  node: graphql`
    fragment TokenList_node on MeUser {
      id
      api_tokens {
        id
        name
        created_at
        expires_at
        last_used_at
        masked_token
      }
    }
  `,
});
