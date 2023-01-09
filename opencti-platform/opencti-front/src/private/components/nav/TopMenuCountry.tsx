import React, { FunctionComponent } from 'react';
import { Link, useLocation, useParams } from 'react-router-dom';
import Button from '@mui/material/Button';
import { ArrowForwardIosOutlined, FlagOutlined } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../components/i18n';
import Security from '../../../utils/Security';
import {
  KNOWLEDGE_KNGETEXPORT,
  KNOWLEDGE_KNUPLOAD,
} from '../../../utils/hooks/useGranted';
import { Theme } from '../../../components/Theme';

const styles = makeStyles<Theme>((theme) => ({
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

const TopMenuCountry: FunctionComponent = () => {
  const location = useLocation();
  const { t } = useFormatter();
  const classes = styles();
  const { countryId } = useParams() as { countryId: string };

  return (
    <div>
      <Button
        component={Link}
        to="/dashboard/locations/countries"
        variant="contained"
        size="small"
        color="primary"
        classes={{ root: classes.buttonHome }}
      >
        <FlagOutlined className={classes.icon} fontSize="small" />
        {t('Countries')}
      </Button>
      <ArrowForwardIosOutlined
        color="primary"
        classes={{ root: classes.arrow }}
      />
      <Button
        component={Link}
        to={`/dashboard/locations/countries/${countryId}`}
        variant={
          location.pathname === `/dashboard/locations/countries/${countryId}`
            ? 'contained'
            : 'text'
        }
        size="small"
        color={
          location.pathname === `/dashboard/locations/countries/${countryId}`
            ? 'secondary'
            : 'primary'
        }
        classes={{ root: classes.button }}
      >
        {t('Overview')}
      </Button>
      <Button
        component={Link}
        to={`/dashboard/locations/countries/${countryId}/knowledge`}
        variant={
          location.pathname.includes(
            `/dashboard/locations/countries/${countryId}/knowledge`,
          )
            ? 'contained'
            : 'text'
        }
        size="small"
        color={
          location.pathname.includes(
            `/dashboard/locations/countries/${countryId}/knowledge`,
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
        to={`/dashboard/locations/countries/${countryId}/analysis`}
        variant={
          location.pathname
          === `/dashboard/locations/countries/${countryId}/analysis`
            ? 'contained'
            : 'text'
        }
        size="small"
        color={
          location.pathname
          === `/dashboard/locations/countries/${countryId}/analysis`
            ? 'secondary'
            : 'primary'
        }
        classes={{ root: classes.button }}
      >
        {t('Analysis')}
      </Button>
      <Security needs={[KNOWLEDGE_KNUPLOAD, KNOWLEDGE_KNGETEXPORT]}>
        <Button
          component={Link}
          to={`/dashboard/locations/countries/${countryId}/files`}
          variant={
            location.pathname
            === `/dashboard/locations/countries/${countryId}/files`
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname
            === `/dashboard/locations/countries/${countryId}/files`
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
        >
          {t('Data')}
        </Button>
      </Security>
      <Button
        component={Link}
        to={`/dashboard/locations/countries/${countryId}/history`}
        variant={
          location.pathname
          === `/dashboard/locations/countries/${countryId}/history`
            ? 'contained'
            : 'text'
        }
        size="small"
        color={
          location.pathname
          === `/dashboard/locations/countries/${countryId}/history`
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

export default TopMenuCountry;
