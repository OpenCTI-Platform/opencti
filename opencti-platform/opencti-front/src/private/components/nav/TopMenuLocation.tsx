import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import Button from '@mui/material/Button';
import { CityVariantOutline, ImageArea } from 'mdi-material-ui';
import {
  PublicOutlined,
  PlaceOutlined,
  FlagOutlined,
} from '@mui/icons-material';
import { Theme } from '@mui/material/styles/createTheme';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../components/i18n';
import { useIsHiddenEntity } from '../../../utils/hooks/useEntitySettings';

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
  const classes = useStyles();
  const location = useLocation();
  const { t } = useFormatter();

  return (
    <div>
      {!useIsHiddenEntity('Region') && (
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
          <PublicOutlined className={classes.icon} fontSize="small" />
          {t('Regions')}
        </Button>
      )}
      {!useIsHiddenEntity('Country') && (
        <Button
          component={Link}
          to="/dashboard/locations/countries"
          variant={
            location.pathname.includes('/dashboard/locations/countries')
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname.includes('/dashboard/locations/countries')
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
        >
          <FlagOutlined className={classes.icon} fontSize="small" />
          {t('Countries')}
        </Button>
      )}
      {!useIsHiddenEntity('City') && (
      {!isEntityTypeHidden('AdministrativeArea') && (
          <Button
              component={Link}
              to="/dashboard/locations/areas"
              variant={
                location.pathname.includes('/dashboard/locations/areas')
                  ? 'contained'
                  : 'text'
              }
              size="small"
              color={
                location.pathname.includes('/dashboard/locations/areas')
                  ? 'secondary'
                  : 'primary'
              }
              classes={{ root: classes.button }}
          >
            <ImageArea className={classes.icon} fontSize="small"/>
            {t('Areas')}
          </Button>
      )}
      {!isEntityTypeHidden('City') && (
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
      {!useIsHiddenEntity('Position') && (
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
