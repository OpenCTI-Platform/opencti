import { makeStyles } from '@mui/styles';
import { Link, useLocation } from 'react-router-dom';
import { Button } from '@mui/material';
import { ArrowForwardIosTwoTone, MonetizationOnOutlined } from '@mui/icons-material';
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

const TopMenuFinancialAsset = ({ id: assetId }: { id: string }) => {
  const location = useLocation();
  const classes = useStyles();
  const { t } = useFormatter();

  return (
    <div>
      <Button
        component={Link}
        to="/dashboard/financial/assets"
        variant="contained"
        size="small"
        color="primary"
        classes={{ root: classes.buttonHome }}
      >
        <MonetizationOnOutlined className={classes.icon} fontSize="small" />
        {t('Assets')}
      </Button>
      <ArrowForwardIosTwoTone
        color="primary"
        classes={{ root: classes.arrow }}
      />
      <Button
        component={Link}
        to={`/dashboard/financial/assets/${assetId}`}
        variant={
          location.pathname === `/dashboard/financial/assets/${assetId}`
            ? 'contained'
            : 'text'
        }
        size="small"
        color={
          location.pathname === `/dashboard/financial/assets/${assetId}`
            ? 'secondary'
            : 'primary'
        }
        classes={{ root: classes.button }}
      >
        {t('Overview')}
      </Button>
      <Button
        component={Link}
        to={`/dashboard/financial/assets/${assetId}/knowledge`}
        variant={
          location.pathname.includes(
            `/dashboard/financial/assets/${assetId}/knowledge`,
          )
            ? 'contained'
            : 'text'
        }
        size="small"
        color={
          location.pathname.includes(
            `/dashboard/financial/assets/${assetId}/knowledge`,
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
        to={`/dashboard/financial/assets/${assetId}/history`}
        variant={
          location.pathname
            === `/dashboard/financial/assets/${assetId}/history`
            ? 'contained'
            : 'text'
        }
        size="small"
        color={
          location.pathname
            === `/dashboard/financial/assets/${assetId}/history`
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

export default TopMenuFinancialAsset;
