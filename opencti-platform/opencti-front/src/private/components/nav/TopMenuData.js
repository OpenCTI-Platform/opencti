import React, { useContext } from 'react';
import { Link, useLocation } from 'react-router-dom';
import Button from '@mui/material/Button';
import { makeStyles } from '@mui/styles';
import { useFormatter } from '../../../components/i18n';
import {
  KNOWLEDGE,
  MODULES,
  TAXIIAPI_SETCOLLECTIONS,
  SETTINGS,
  KNOWLEDGE_KNUPDATE,
  UserContext,
  granted,
} from '../../../utils/Security';

const useStyles = makeStyles((theme) => ({
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

const TopMenuData = () => {
  const { t } = useFormatter();
  const classes = useStyles();
  const location = useLocation();
  const { me } = useContext(UserContext);
  const isKnowledgeReader = granted(me, [KNOWLEDGE]);
  const isKnowledgeEditor = granted(me, [KNOWLEDGE_KNUPDATE]);
  const isConnectorReader = granted(me, [MODULES]);
  const isSettingsManager = granted(me, [SETTINGS]);
  const isSharingManager = granted(me, [TAXIIAPI_SETCOLLECTIONS]);
  return (
    <div>
      {isKnowledgeReader && (
        <Button
          component={Link}
          to="/dashboard/data/entities"
          variant={
            location.pathname === '/dashboard/data/entities'
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname === '/dashboard/data/entities'
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
        >
          {t('Entities')}
        </Button>
      )}
      {isKnowledgeReader && (
        <Button
          component={Link}
          to="/dashboard/data/relationships"
          variant={
            location.pathname === '/dashboard/data/relationships'
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname === '/dashboard/data/relationships'
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
        >
          {t('Relationships')}
        </Button>
      )}
      {isKnowledgeEditor && (
        <Button
          component={Link}
          to="/dashboard/data/tasks"
          variant={
            location.pathname === '/dashboard/data/tasks' ? 'contained' : 'text'
          }
          size="small"
          color={
            location.pathname === '/dashboard/data/tasks'
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
        >
          {t('Background tasks')}
        </Button>
      )}
      {isConnectorReader && (
        <Button
          component={Link}
          to="/dashboard/data/connectors"
          variant={
            location.pathname.includes('/dashboard/data/connectors')
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname.includes('/dashboard/data/connectors')
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
        >
          {t('Connectors')}
        </Button>
      )}
      {isSettingsManager && (
        <Button
          component={Link}
          to="/dashboard/data/sync"
          variant={
            location.pathname === '/dashboard/data/sync' ? 'contained' : 'text'
          }
          size="small"
          color={
            location.pathname === '/dashboard/data/sync'
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
        >
          {t('Synchronization')}
        </Button>
      )}
      {isSharingManager && (
        <Button
          component={Link}
          to="/dashboard/data/sharing"
          variant={
            location.pathname.includes('/dashboard/data/sharing')
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname.includes('/dashboard/data/sharing')
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
        >
          {t('Data sharing')}
        </Button>
      )}
    </div>
  );
};

export default TopMenuData;
