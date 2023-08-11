import { Chip, Grid, Paper, Typography } from '@mui/material';
import { FunctionComponent } from 'react';
import { makeStyles } from '@mui/styles';
import AccountBalances from './AccountBalances';
import { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import { Account_financialAccount$data } from './__generated__/Account_financialAccount.graphql';
import { valToKey } from '../../../../utils/Localization';
import { FinancialAccountStatus, FinancialAccountType, displayCurrencyCode } from './AccountCreation';

const useStyles = makeStyles<Theme>(() => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
  chip: {
    fontSize: 12,
    height: 25,
    marginRight: 7,
    textTransform: 'uppercase',
    borderRadius: '0',
    width: '100%',
    backgroundColor: 'rgba(229,152,137, 0.08)',
    color: '#e59889',
  },
}));

interface AccountDetailsComponentProps {
  account: Account_financialAccount$data;
}

const AccountDetailsComponent: FunctionComponent<
AccountDetailsComponentProps
> = ({ account }: AccountDetailsComponentProps) => {
  const classes = useStyles();
  const { t } = useFormatter();

  return (
    <div style={{ height: '100%' }}>
      <Typography variant="h4" gutterBottom={true}>
        {t('Details')}
      </Typography>
      <Paper classes={{ root: classes.paper }} variant="outlined">
        <Grid container={true} spacing={3}>
          <Grid item={true} xs={4}>
            <Typography variant="h3" gutterBottom={true}>
              {t('Currency Code')}
            </Typography>
            <Chip
              classes={{ root: classes.chip }}
              label={displayCurrencyCode(account?.currency_code || t('Unknown'))}
            />
          </Grid>
          <Grid item={true} xs={4}>
            <Typography variant="h3" gutterBottom={true}>
              {t('Account Type')}
            </Typography>
            <Chip
              classes={{ root: classes.chip }}
              label={t(valToKey(account?.financial_account_type, FinancialAccountType))}
            />
          </Grid>
          <Grid item={true} xs={4}>
            <Typography variant="h3" gutterBottom={true}>
              {t('Account Status')}
            </Typography>
            <Chip
              classes={{ root: classes.chip }}
              label={t(valToKey(account?.financial_account_status, FinancialAccountStatus))}
            />
          </Grid>
          <Grid item={true} xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t('Account Number')}
            </Typography>
            <Chip
              classes={{ root: classes.chip }}
              label={account?.financial_account_number}
            />
          </Grid>
          <Grid item={true} xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t('IBAN')}
            </Typography>
            <Chip
              classes={{ root: classes.chip }}
              label={account?.international_bank_account_number}
            />
          </Grid>
          <Grid item={true} xs={12}>
            <Typography variant="h3" gutterBottom={true}>
              {t('Account Balances')}
            </Typography>
            <AccountBalances
              account={account}
              isEditable={true}
            />
          </Grid>
        </Grid>
      </Paper>
    </div>
  );
};

export default AccountDetailsComponent;
