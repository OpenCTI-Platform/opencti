import { makeStyles } from '@mui/styles';
import { Link, useLocation } from 'react-router-dom';
import { Button } from '@mui/material';
import { ArrowForwardIosTwoTone, SavingsOutlined } from '@mui/icons-material';
import { useFormatter } from '../../../components/i18n';
import { Theme } from '../../../components/Theme';

const useStyles = makeStyles<Theme>((theme) => ({
  buttonHome: {
    marginRight: theme.spacing(2),
    padding: '0 5px 0 5px',
    minHeight: 20,
    textTransform: 'none',
  },
  button: {
    marginRight: theme.spacing(2),
    padding: '0 5px 0 5px',
    minHeight: 20,
    minWidth: 20,
    textTransform: 'none',
  },
  icon: {
    marginRight: theme.spacing(1),
  },
  arrow: {
    verticalAlign: 'middle',
    marginRight: 10,
  },
}));

const TopMenuFinancialAccount = ({ id: accountId }: { id: string }) => {
  const location = useLocation();
  const classes = useStyles();
  const { t } = useFormatter();

  return (
    <div>
      <Button
        component={Link}
        to="/dashboard/financial/accounts"
        variant="contained"
        size="small"
        color="primary"
        classes={{ root: classes.buttonHome }}
      >
        <SavingsOutlined className={classes.icon} fontSize="small" />
        {t('Accounts')}
      </Button>
      <ArrowForwardIosTwoTone
        color="primary"
        classes={{ root: classes.arrow }}
      />
      <Button
        component={Link}
        to={`/dashboard/financial/accounts/${accountId}`}
        variant={
          location.pathname === `/dashboard/financial/accounts/${accountId}`
            ? 'contained'
            : 'text'
        }
        size="small"
        color={
          location.pathname === `/dashboard/financial/accounts/${accountId}`
            ? 'secondary'
            : 'primary'
        }
        classes={{ root: classes.button }}
      >
        {t('Overview')}
      </Button>
      <Button
        component={Link}
        to={`/dashboard/financial/accounts/${accountId}/knowledge`}
        variant={
          location.pathname.includes(
            `/dashboard/financial/accounts/${accountId}/knowledge`,
          )
            ? 'contained'
            : 'text'
        }
        size="small"
        color={
          location.pathname.includes(
            `/dashboard/financial/accounts/${accountId}/knowledge`,
          )
            ? 'secondary'
            : 'primary'
        }
        classes={{ root: classes.button }}
      >
        {t('Knowledge')}
      </Button>
      <Button
        component={Link}
        to={`/dashboard/financial/accounts/${accountId}/history`}
        variant={
          location.pathname
          === `/dashboard/financial/accounts/${accountId}/history`
            ? 'contained'
            : 'text'
        }
        size="small"
        color={
          location.pathname
          === `/dashboard/financial/accounts/${accountId}/history`
            ? 'secondary'
            : 'primary'
        }
        classes={{ root: classes.button }}
      >
        {t('History')}
      </Button>
    </div>
  );
};

export default TopMenuFinancialAccount;
