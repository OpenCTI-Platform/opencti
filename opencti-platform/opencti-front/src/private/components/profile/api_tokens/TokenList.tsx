import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Paper, IconButton, Tooltip } from '@mui/material';
import { Delete } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
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

interface TokenListProps {
  node: TokenList_node$data;
}

export const TokenListBase: React.FC<TokenListProps> = ({ node }) => {
  const classes = useStyles();
  const { t_i18n, nsdt } = useFormatter();
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

  const handleRevoke = (id: string) => {
    // TODO: Implement revocation (confimation dialog first?)
    console.log('Revoke token', id);
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
    <TableContainer component={Paper} variant="outlined" className={classes.container}>
      <Table className={classes.table} size="small" aria-label="token list">
        <TableHead>
          <TableRow>
            <TableCell>{t_i18n('Name')}</TableCell>
            <TableCell>{t_i18n('Token')}</TableCell>
            <TableCell>{t_i18n('Created At')}</TableCell>
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
              <TableCell>
                {token.masked_token}
              </TableCell>
              <TableCell>{nsdt(token.created_at)}</TableCell>
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
                    onClick={() => handleRevoke(token.id)}
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
  );
};

export default createFragmentContainer(TokenListBase, {
  node: graphql`
    fragment TokenList_node on MeUser {
      api_tokens {
        id
        name
        created_at
        expires_at
        masked_token
      }
    }
  `,
});
