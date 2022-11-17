import React, { useContext } from 'react';
import { Theme } from '@mui/material/styles/createTheme';
import { Link, useLocation } from 'react-router-dom';
import Button from '@mui/material/Button';
import { makeStyles } from '@mui/styles';
import { useFormatter } from '../../../components/i18n';
import {
  granted,
  KNOWLEDGE,
  KNOWLEDGE_KNUPDATE,
  MODULES,
  SETTINGS,
  TAXIIAPI_SETCOLLECTIONS,
  UserContext,
  UserContextType,
} from '../../../utils/Security';

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

const TopMenuData = () => {
  const { t } = useFormatter();
  const classes = useStyles();
  const location = useLocation();
  const { me } = useContext<UserContextType>(UserContext);
  const isKnowledgeReader = granted(me, [KNOWLEDGE]);
  const isKnowledgeEditor = granted(me, [KNOWLEDGE_KNUPDATE]);
  const isConnectorReader = granted(me, [MODULES]);
  const isSettingsManager = granted(me, [SETTINGS]);
  const isSharingManager = granted(me, [TAXIIAPI_SETCOLLECTIONS]);
  const isCompatiblePath = (path?: string) => (path ? location.pathname.includes(path) : location.pathname === path);
  const getVariant = (path: string) => (isCompatiblePath(path) ? 'contained' : 'text');
  const getColor = (path: string) => (isCompatiblePath(path) ? 'secondary' : 'primary');
  return (
    <div>
      {isKnowledgeReader && (
        <Button
          component={Link}
          size="small"
          to="/dashboard/data/entities"
          variant={getVariant('/dashboard/data/entities')}
          color={getColor('/dashboard/data/entities')}
          classes={{ root: classes.button }}
        >
          {t('Entities')}
        </Button>
      )}
      {isKnowledgeReader && (
        <Button
          component={Link}
          size="small"
          to="/dashboard/data/relationships"
          variant={getVariant('/dashboard/data/relationships')}
          color={getColor('/dashboard/data/relationships')}
          classes={{ root: classes.button }}
        >
          {t('Relationships')}
        </Button>
      )}
      {isKnowledgeEditor && (
        <Button
          component={Link}
          size="small"
          to="/dashboard/data/tasks"
          variant={getVariant('/dashboard/data/tasks')}
          color={getColor('/dashboard/data/tasks')}
          classes={{ root: classes.button }}
        >
          {t('Background tasks')}
        </Button>
      )}
      {isConnectorReader && (
        <Button
          component={Link}
          size="small"
          to="/dashboard/data/connectors"
          variant={getVariant('/dashboard/data/connectors')}
          color={getColor('/dashboard/data/connectors')}
          classes={{ root: classes.button }}
        >
          {t('Connectors')}
        </Button>
      )}
      {isSettingsManager && (
        <Button
          component={Link}
          size="small"
          to="/dashboard/data/sync"
          variant={getVariant('/dashboard/data/sync')}
          color={getColor('/dashboard/data/sync')}
          classes={{ root: classes.button }}
        >
          {t('Synchronization')}
        </Button>
      )}
      {isSharingManager && (
        <Button
          component={Link}
          size="small"
          to="/dashboard/data/sharing"
          variant={getVariant('/dashboard/data/sharing')}
          color={getColor('/dashboard/data/sharing')}
          classes={{ root: classes.button }}
        >
          {t('Data sharing')}
        </Button>
      )}
    </div>
  );
};

export default TopMenuData;
