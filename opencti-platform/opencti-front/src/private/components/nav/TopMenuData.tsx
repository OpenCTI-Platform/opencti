import React from 'react';
import { Theme } from '@mui/material/styles/createTheme';
import { Link, useLocation } from 'react-router-dom';
import Button from '@mui/material/Button';
import Tooltip from '@mui/material/Tooltip';
import { makeStyles } from '@mui/styles';
import { useFormatter } from '../../../components/i18n';
import useGranted, {
  KNOWLEDGE,
  KNOWLEDGE_KNUPDATE,
  MODULES,
  SETTINGS,
  TAXIIAPI_SETCOLLECTIONS,
} from '../../../utils/hooks/useGranted';
import { SYNC_MANAGER, TASK_MANAGER } from '../../../utils/platformModulesHelper';
import useAuth from '../../../utils/hooks/useAuth';

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
  const { platformModuleHelpers } = useAuth();
  const isKnowledgeReader = useGranted([KNOWLEDGE]);
  const isKnowledgeEditor = useGranted([KNOWLEDGE_KNUPDATE]);
  const isConnectorReader = useGranted([MODULES]);
  const isSettingsManager = useGranted([SETTINGS]);
  const isSharingManager = useGranted([TAXIIAPI_SETCOLLECTIONS]);
  const isCompatiblePath = (path?: string) => (path ? location.pathname.includes(path) : location.pathname === path);
  const getVariant = (path: string) => (isCompatiblePath(path) ? 'contained' : 'text');
  const getColor = (path: string) => (isCompatiblePath(path) ? 'secondary' : 'primary');
  return (
    <div>
      {isKnowledgeReader && (
        <Button component={Link} size="small" to="/dashboard/data/entities"
          variant={getVariant('/dashboard/data/entities')}
          color={getColor('/dashboard/data/entities')}
          classes={{ root: classes.button }}>
          {t('Entities')}
        </Button>
      )}
      {isKnowledgeReader && (
        <Button component={Link} size="small" to="/dashboard/data/relationships"
          variant={getVariant('/dashboard/data/relationships')}
          color={getColor('/dashboard/data/relationships')}
          classes={{ root: classes.button }}>
          {t('Relationships')}
        </Button>
      )}
      {isKnowledgeEditor && (
        <Tooltip title={platformModuleHelpers.generateDisableMessage(TASK_MANAGER)}>
          <span>
            <Button component={Link} size="small" to="/dashboard/data/tasks"
              disabled={!platformModuleHelpers.isTasksManagerEnable()}
              variant={getVariant('/dashboard/data/tasks')}
              color={getColor('/dashboard/data/tasks')}
              classes={{ root: classes.button }}>
              {t('Background tasks')}
            </Button>
          </span>
        </Tooltip>
      )}
      {isConnectorReader && (
        <Button component={Link} size="small" to="/dashboard/data/connectors"
          variant={getVariant('/dashboard/data/connectors')}
          color={getColor('/dashboard/data/connectors')}
          classes={{ root: classes.button }}>
          {t('Connectors')}
        </Button>
      )}
      {isSettingsManager && (
        <Tooltip title={platformModuleHelpers.generateDisableMessage(SYNC_MANAGER)}>
          <span>
            <Button component={Link} size="small" to="/dashboard/data/sync"
              disabled={!platformModuleHelpers.isSyncManagerEnable()}
              variant={getVariant('/dashboard/data/sync')}
              color={getColor('/dashboard/data/sync')}
              classes={{ root: classes.button }}>
              {t('Synchronization')}
            </Button>
          </span>
        </Tooltip>
      )}
      {isSharingManager && (
        <Button component={Link} size="small" to="/dashboard/data/sharing"
          variant={getVariant('/dashboard/data/sharing')}
          color={getColor('/dashboard/data/sharing')}
          classes={{ root: classes.button }}>
          {t('Data sharing')}
        </Button>
      )}
    </div>
  );
};

export default TopMenuData;
