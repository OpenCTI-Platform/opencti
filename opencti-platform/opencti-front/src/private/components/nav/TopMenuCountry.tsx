import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import Button from '@mui/material/Button';
import { ArrowForwardIosOutlined, FlagOutlined } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../components/i18n';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNGETEXPORT, KNOWLEDGE_KNUPLOAD } from '../../../utils/hooks/useGranted';
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

const TopMenuCountry = ({ id: countryId }: { id: string }) => {
  const location = useLocation();
  const { t } = useFormatter();
  const classes = useStyles();
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
        disabled={!countryId}
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
        disabled={!countryId}
      >
        {t('Knowledge')}
      </Button>
      <Button
        component={Link}
        to={`/dashboard/locations/countries/${countryId}/analyses`}
        variant={
          location.pathname
          === `/dashboard/locations/countries/${countryId}/analyses`
            ? 'contained'
            : 'text'
        }
        size="small"
        color={
          location.pathname
          === `/dashboard/locations/countries/${countryId}/analyses`
            ? 'secondary'
            : 'primary'
        }
        classes={{ root: classes.button }}
        disabled={!countryId}
      >
        {t('Analyses')}
      </Button>
      <Button
        component={Link}
        to={`/dashboard/locations/countries/${countryId}/sightings`}
        variant={
          location.pathname
          === `/dashboard/locations/countries/${countryId}/sightings`
            ? 'contained'
            : 'text'
        }
        size="small"
        color={
          location.pathname
          === `/dashboard/locations/countries/${countryId}/sightings`
            ? 'secondary'
            : 'primary'
        }
        classes={{ root: classes.button }}
        disabled={!countryId}
      >
        {t('Sightings')}
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
          disabled={!countryId}
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
        disabled={!countryId}
      >
        {t('History')}
      </Button>
    </div>
  );
};

export default TopMenuCountry;
