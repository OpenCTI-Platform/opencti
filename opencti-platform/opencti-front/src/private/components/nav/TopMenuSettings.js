import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import Tooltip from '@mui/material/Tooltip';
import Button from '@mui/material/Button';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../components/i18n';
import Security from '../../../utils/Security';
import { SETTINGS_SETACCESSES, SETTINGS_SETLABELS, SETTINGS_SETMARKINGS } from '../../../utils/hooks/useGranted';
import useAuth from '../../../utils/hooks/useAuth';
import { RETENTION_MANAGER, RULE_ENGINE } from '../../../utils/platformModulesHelper';

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

const TopMenuSettings = () => {
  const { platformModuleHelpers } = useAuth();
  const { t } = useFormatter();
  const location = useLocation();
  const classes = useStyles();

  return (
        <div>
            <Button component={Link} size="small" to="/dashboard/settings"
                variant={location.pathname === '/dashboard/settings' || location.pathname === '/dashboard/settings/about' ? 'contained' : 'text'}
                color={location.pathname === '/dashboard/settings' || location.pathname === '/dashboard/settings/about' ? 'secondary' : 'primary'}
                classes={{ root: classes.button }}>
                {t('Parameters')}
            </Button>
            <Security needs={[SETTINGS_SETMARKINGS, SETTINGS_SETACCESSES]}>
                <Button component={Link} size="small" to="/dashboard/settings/accesses"
                    variant={location.pathname.includes('/dashboard/settings/accesses') ? 'contained' : 'text'}
                    color={location.pathname.includes('/dashboard/settings/accesses') ? 'secondary' : 'primary'}
                    classes={{ root: classes.button }}>
                    {t('Security')}
                </Button>
            </Security>
            <Button component={Link} size="small" to="/dashboard/settings/entity_types"
                    variant={location.pathname.includes('/dashboard/settings/entity_types') ? 'contained' : 'text'}
                    color={location.pathname.includes('/dashboard/settings/entity_types') ? 'secondary' : 'primary'}
                    classes={{ root: classes.button }}>
                {t('Entity types')}
            </Button>
            <Tooltip title={platformModuleHelpers.generateDisableMessage(RETENTION_MANAGER)}>
                    <span>
                        <Button component={Link} size="small" to="/dashboard/settings/retention"
                                disabled={!platformModuleHelpers.isRetentionManagerEnable()}
                                variant={location.pathname.includes('/dashboard/settings/retention') ? 'contained' : 'text'}
                                color={location.pathname.includes('/dashboard/settings/retention') ? 'secondary' : 'primary'}
                                classes={{ root: classes.button }}>
                            {t('Retention policies')}
                        </Button>
                    </span>
            </Tooltip>
            <Tooltip title={platformModuleHelpers.generateDisableMessage(RULE_ENGINE)}>
                    <span>
                        <Button component={Link} size="small" to="/dashboard/settings/rules"
                                disabled={!platformModuleHelpers.isRuleEngineEnable()}
                                variant={location.pathname.includes('/dashboard/settings/rules') ? 'contained' : 'text'}
                                color={location.pathname.includes('/dashboard/settings/rules') ? 'secondary' : 'primary'}
                                classes={{ root: classes.button }}>
                            {t('Rules engine')}
                        </Button>
                    </span>
            </Tooltip>
            <Security needs={[SETTINGS_SETLABELS]}>
                <Button component={Link} size="small" to="/dashboard/settings/vocabularies"
                    variant={location.pathname.includes('/dashboard/settings/vocabularies') ? 'contained' : 'text'}
                    color={location.pathname.includes('/dashboard/settings/vocabularies') ? 'secondary' : 'primary'}
                    classes={{ root: classes.button }}>
                    {t('Labels & Attributes')}
                </Button>
            </Security>
        </div>
  );
};

export default TopMenuSettings;
