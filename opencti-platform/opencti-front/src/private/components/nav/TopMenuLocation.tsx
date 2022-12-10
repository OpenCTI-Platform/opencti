import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import Button from '@mui/material/Button';
import { CityVariantOutline } from 'mdi-material-ui';
import { MapOutlined, SpeakerNotesOutlined, PlaceOutlined } from '@mui/icons-material';
import { Theme } from '@mui/material/styles/createTheme';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../components/i18n';
import useHelper from '../../../utils/hooks/useHelper';

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

const TopMenuLocation = () => {
  const location = useLocation();
  const { t } = useFormatter();
  const classes = useStyles();
  const { isEntityTypeHidden } = useHelper();

  return (
      <div>
        {!isEntityTypeHidden('Locations')
          && !isEntityTypeHidden('Regions') && (
            <Button
              component={Link}
              to="/dashboard/locations/regions"
              variant={
                location.pathname === '/dashboard/locations/regions'
                  ? 'contained'
                  : 'text'
              }
              size="small"
              color={
                location.pathname === '/dashboard/locations/regions'
                  ? 'secondary'
                  : 'primary'
              }
              classes={{ root: classes.button }}
            >
              <SpeakerNotesOutlined
                className={classes.icon}
                fontSize="small"
              />
              {t('Regions')}
            </Button>
        )}
        {!isEntityTypeHidden('Country') && (
          <Button
            component={Link}
            to="/dashboard/locations/countries"
            variant={
              location.pathname.includes(
                '/dashboard/locations/countries',
              )
                ? 'contained'
                : 'text'
            }
            size="small"
            color={
              location.pathname.includes(
                '/dashboard/locations/countries',
              )
                ? 'secondary'
                : 'primary'
            }
            classes={{ root: classes.button }}
          >
            <MapOutlined className={classes.icon} fontSize="small" />
            {t('Countries')}
          </Button>
        )}
        {!isEntityTypeHidden('Cities') && (
          <Button
            component={Link}
            to="/dashboard/locations/cities"
            variant={
              location.pathname === '/dashboard/locations/cities'
                ? 'contained'
                : 'text'
            }
            size="small"
            color={
              location.pathname === '/dashboard/locations/cities'
                ? 'secondary'
                : 'primary'
            }
            classes={{ root: classes.button }}
          >
            <CityVariantOutline className={classes.icon} fontSize="small" />
            {t('Cities')}
          </Button>
        )}
        {!isEntityTypeHidden('Positions') && (
          <Button
            component={Link}
            to="/dashboard/locations/positions"
            variant={
              location.pathname === '/dashboard/locations/positions'
                ? 'contained'
                : 'text'
            }
            size="small"
            color={
              location.pathname === '/dashboard/locations/positions'
                ? 'secondary'
                : 'primary'
            }
            classes={{ root: classes.button }}
          >
            <PlaceOutlined className={classes.icon} fontSize="small" />
            {t('Positions')}
          </Button>
        )}
      </div>
  );
};

export default TopMenuLocation;
