import { makeStyles } from '@mui/styles';
import { Button } from '@mui/material';
import { Link, useLocation } from 'react-router-dom';
import { SavingsOutlined, MonetizationOnOutlined } from '@mui/icons-material';
import { useIsHiddenEntity } from '../../../utils/hooks/useEntitySettings';
import { Theme } from '../../../components/Theme';
import { useFormatter } from '../../../components/i18n';

const useStyles = makeStyles<Theme>((theme) => ({
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
}));

const TopMenuFinancial = () => {
  const classes = useStyles();
  const location = useLocation();
  const { t } = useFormatter();

  return (
    <div>
      {!useIsHiddenEntity('Financial-Account') && (
        <Button
          component={Link}
          to="/dashboard/financial/accounts"
          variant={
            location.pathname === '/dashboard/financial/accounts'
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname === '/dashboard/financial/accounts'
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
        >
          <SavingsOutlined className={classes.icon} fontSize="small" />
          {t('Accounts')}
        </Button>
      )}
      {!useIsHiddenEntity('Financial-Asset') && (
        <Button
          component={Link}
          to="/dashboard/financial/assets"
          variant={
            location.pathname === '/dashboard/financial/assets'
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname === '/dashboard/financial/assets'
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
        >
          <MonetizationOnOutlined className={classes.icon} fontSize="small" />
          {t('Assets')}
        </Button>
      )}
    </div>
  );
};

export default TopMenuFinancial;
