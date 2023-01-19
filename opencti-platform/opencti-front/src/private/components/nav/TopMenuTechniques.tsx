import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import Button from '@mui/material/Button';
import { LockPattern, ProgressWrench } from 'mdi-material-ui';
import {
  SpeakerNotesOutlined,
  StreamOutlined,
  SourceOutlined,
} from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../components/i18n';
import { Theme } from '../../../components/Theme';
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

const TopMenuTechniques = () => {
  const location = useLocation();
  const { t } = useFormatter();
  const classes = useStyles();
  return (
    <div>
      {!useIsHiddenEntity('Attack-Pattern') && (
          <Button
            component={Link}
            to="/dashboard/techniques/attack_patterns"
            variant={
              location.pathname.includes(
                '/dashboard/techniques/attack_patterns',
              )
                ? 'contained'
                : 'text'
            }
            size="small"
            color={
              location.pathname.includes(
                '/dashboard/techniques/attack_patterns',
              )
                ? 'secondary'
                : 'primary'
            }
            classes={{ root: classes.button }}
          >
            <LockPattern className={classes.icon} fontSize="small" />
            {t('Attack Patterns')}
          </Button>
      )}
      {!useIsHiddenEntity('Narrative') && (
        <Button
          component={Link}
          to="/dashboard/techniques/narratives"
          variant={
            location.pathname === '/dashboard/techniques/narratives'
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname === '/dashboard/techniques/narratives'
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
        >
          <SpeakerNotesOutlined className={classes.icon} fontSize="small" />
          {t('Narratives')}
        </Button>
      )}
      {!useIsHiddenEntity('Course-Of-Action') && (
        <Button
          component={Link}
          to="/dashboard/techniques/courses_of_action"
          variant={
            location.pathname === '/dashboard/techniques/courses_of_action'
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname === '/dashboard/techniques/courses_of_action'
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
        >
          <ProgressWrench className={classes.icon} fontSize="small" />
          {t('Courses of action')}
        </Button>
      )}
      {!useIsHiddenEntity('Data-Component') && (
        <Button
          component={Link}
          to="/dashboard/techniques/data_components"
          variant={
            location.pathname === '/dashboard/techniques/data_components'
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname === '/dashboard/techniques/data_components'
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
        >
          <SourceOutlined className={classes.icon} fontSize="small" />
          {t('Data components')}
        </Button>
      )}
      {!useIsHiddenEntity('Data-Source') && (
        <Button
          component={Link}
          to="/dashboard/techniques/data_sources"
          variant={
            location.pathname === '/dashboard/techniques/data_sources'
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname === '/dashboard/techniques/data_sources'
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
        >
          <StreamOutlined className={classes.icon} fontSize="small" />
          {t('Data sources')}
        </Button>
      )}
    </div>
  );
};

export default TopMenuTechniques;
