import React from 'react';
import type { Theme } from '@mui/material/styles/createTheme';
import { Link, useLocation } from 'react-router-dom';
import Tooltip from '@mui/material/Tooltip';
import { makeStyles } from '@mui/styles';
import { MenuItem, MenuList } from '@mui/material';
import { useFormatter } from '../../../components/i18n';
import useGranted, {
  KNOWLEDGE,
  KNOWLEDGE_KNUPDATE,
  MODULES,
  SETTINGS,
  SETTINGS_SETACCESSES,
  TAXIIAPI_SETCOLLECTIONS,
  TAXIIAPI_SETCSVMAPPERS,
} from '../../../utils/hooks/useGranted';
import { TASK_MANAGER } from '../../../utils/platformModulesHelper';
import useAuth from '../../../utils/hooks/useAuth';

const useStyles = makeStyles<Theme>(() => ({
  leftButton: {
    padding: '3px 4px 3px 45px',
    minHeight: 20,
    minWidth: 20,
    textWrap: 'balance',
    lineHeight: '15px',
    textTransform: 'none',
  },
}));

const LeftMenuData = () => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  const location = useLocation();
  const { platformModuleHelpers } = useAuth();
  const isKnowledgeReader = useGranted([KNOWLEDGE]);
  const isKnowledgeUpdater = useGranted([KNOWLEDGE_KNUPDATE]);
  const isConnectorReader = useGranted([MODULES]);
  const isSettingsManager = useGranted([SETTINGS]);
  const isAdministrator = useGranted([SETTINGS_SETACCESSES]);
  const isSharingManager = useGranted([TAXIIAPI_SETCOLLECTIONS]);
  const isCsvMapperUpdater = useGranted([TAXIIAPI_SETCSVMAPPERS]);
  const isCompatiblePath = (path?: string) => (path ? location.pathname.includes(path) : location.pathname === path);
  return (
    <MenuList>
      {isKnowledgeReader && (
        <MenuItem
          component={Link}
          to="/dashboard/data/entities"
          selected={isCompatiblePath('/dashboard/data/entities')}
          dense={true}
          classes={{ root: classes.leftButton }}
        >
          <div style={{
            fontWeight: isCompatiblePath('/dashboard/data/entities')
              ? 'bold'
              : 'normal',
          }}
          >
            {t_i18n('Entities')}
          </div>
        </MenuItem>
      )}
      {isKnowledgeReader && (
        <MenuItem
          component={Link}
          to="/dashboard/data/relationships"
          selected={isCompatiblePath('/dashboard/data/relationships')}
          dense={true}
          classes={{ root: classes.leftButton }}
        >
          <div style={{
            fontWeight: isCompatiblePath('/dashboard/data/relationships')
              ? 'bold'
              : 'normal',
          }}
          >
            {t_i18n('Relationships')}
          </div>
        </MenuItem>
      )}
      {isSettingsManager && (
        <MenuItem
          component={Link}
          to="/dashboard/data/ingestion"
          selected={isCompatiblePath('/dashboard/data/ingestion')}
          dense={true}
          classes={{ root: classes.leftButton }}
        >
          <div style={{
            fontWeight: isCompatiblePath('/dashboard/data/ingestion')
              ? 'bold'
              : 'normal',
          }}
          >
            {t_i18n('Ingestion')}
          </div>
        </MenuItem>
      )}
      {(isKnowledgeUpdater || isAdministrator || isCsvMapperUpdater) && (
        <Tooltip
          title={platformModuleHelpers.generateDisableMessage(TASK_MANAGER)}
        >
          <span>
            <MenuItem
              component={Link}
              to="/dashboard/data/processing"
              disabled={
                !platformModuleHelpers.isPlayBookManagerEnable()
                && !platformModuleHelpers.isTasksManagerEnable()
              }
              selected={isCompatiblePath('/dashboard/data/processing')}
              dense={true}
              classes={{ root: classes.leftButton }}
            >
              <div style={{
                fontWeight: isCompatiblePath('/dashboard/data/processing')
                  ? 'bold'
                  : 'normal',
              }}
              >
                {t_i18n('Processing')}
              </div>
            </MenuItem>
          </span>
        </Tooltip>
      )}
      {isSharingManager && (
        <MenuItem
          component={Link}
          to="/dashboard/data/sharing"
          selected={isCompatiblePath('/dashboard/data/sharing')}
          dense={true}
          classes={{ root: classes.leftButton }}
        >
          <div style={{
            fontWeight: isCompatiblePath('/dashboard/data/sharing')
              ? 'bold'
              : 'normal',
          }}
          >
            {t_i18n('Data sharing')}
          </div>
        </MenuItem>
      )}
      {isConnectorReader && (
        <MenuItem
          component={Link}
          to="/dashboard/data/connectors"
          selected={isCompatiblePath('/dashboard/data/connectors')}
          dense={true}
          classes={{ root: classes.leftButton }}
        >
          <div style={{
            fontWeight: isCompatiblePath('/dashboard/data/connectors')
              ? 'bold'
              : 'normal',
          }}
          >
            {t_i18n('Connectors')}
          </div>
        </MenuItem>
      )}
    </MenuList>
  );
};

export default LeftMenuData;
