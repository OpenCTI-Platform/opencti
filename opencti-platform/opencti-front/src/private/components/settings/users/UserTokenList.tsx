import { Delete } from '@mui/icons-material';
import { Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Tooltip } from '@mui/material';
import { IconButton, Paper } from '@filigran/design-system';
// MIXED FILE, declared as such: the <Paper> tag is the library's, but `TableContainer
// component=` has to stay MUI's Paper — a component passed to MUI as a prop receives MUI props
// (`variant`, `sx`) that the library Paper does not understand.
import MuiPaper from '@mui/material/Paper';
import makeStyles from '@mui/styles/makeStyles';
import React, { useState } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { RecordProxy, RecordSourceSelectorProxy } from 'relay-runtime';
import { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';
import TokenDeleteDialog from '../../profile/api_tokens/TokenDeleteDialog';
import UserTokenCreationDrawer from './UserTokenCreationDrawer';
import { UserTokenList_node$data } from './__generated__/UserTokenList_node.graphql';

const useStyles = makeStyles<Theme>((theme) => ({
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
  openDrawer?: boolean;
  onCloseDrawer: () => void;
}

export const UserTokenList: React.FC<UserTokenListProps> = ({ openDrawer = false, onCloseDrawer, node }) => {
  const classes = useStyles();
  const { t_i18n, nsdt } = useFormatter();
  const [deletingToken, setDeletingToken] = useState<{ id: string; name: string } | null>(null);

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
    <div>
      {tokens.length === 0 ? (
        <Paper padding={0}>
          <div className={classes.empty}>
            {t_i18n('No tokens found.')}
          </div>
        </Paper>
      ) : (
        <TableContainer component={MuiPaper} variant="outlined" sx={{ border: 'none' }}>
          <Table
            size="small"
            aria-label="token list"
            sx={{
              '& .MuiTableRow-root:last-child .MuiTableCell-root': {
                borderBottom: 'none',
              },
            }}
          >
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
                        variant="default"
                        priority="tertiary"
                        size="sm"
                        aria-label={t_i18n('Revoke')}
                        onClick={() => handleOpenDelete({ id: token.id, name: token.name || '' })}
                        icon={<Delete fontSize="small" />}
                      />
                    </Tooltip>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      <TokenDeleteDialog
        token={deletingToken}
        open={deletingToken !== null}
        onClose={handleCloseDelete}
        onDelete={submitDelete}
      />

      <UserTokenCreationDrawer
        userId={node.id}
        open={openDrawer}
        onClose={onCloseDrawer}
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
