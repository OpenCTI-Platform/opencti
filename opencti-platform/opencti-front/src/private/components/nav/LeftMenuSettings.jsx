import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import makeStyles from '@mui/styles/makeStyles';
import { MenuItem, MenuList } from '@mui/material';
import { useFormatter } from '../../../components/i18n';
import Security from '../../../utils/Security';
import { SETTINGS, SETTINGS_SETACCESSES, SETTINGS_SETLABELS, SETTINGS_SETMARKINGS, VIRTUAL_ORGANIZATION_ADMIN } from '../../../utils/hooks/useGranted';
import EEChip from '../common/entreprise_edition/EEChip';

const useStyles = makeStyles(() => ({
  leftButton: {
    padding: '3px 4px 3px 45px',
    minHeight: 20,
    minWidth: 20,
    textWrap: 'balance',
    lineHeight: '15px',
    textTransform: 'none',
  },
}));

const LeftMenuSettings = () => {
  const { t_i18n } = useFormatter();
  const location = useLocation();
  const classes = useStyles();
  return (
    <MenuList>
      <Security needs={[SETTINGS]}>
        <MenuItem
          component={Link}
          dense={true}
          to="/dashboard/settings"
          selected={
            location.pathname === '/dashboard/settings'
            || location.pathname === '/dashboard/settings/about'
          }
          classes={{ root: classes.leftButton }}
        >
          <div style={{
            fontWeight: location.pathname === '/dashboard/settings'
            || location.pathname === '/dashboard/settings/about'
              ? 'bold'
              : 'normal',
          }}
          >
            {t_i18n('Parameters')}
          </div>
        </MenuItem>
      </Security>
      <Security
        needs={[
          SETTINGS_SETMARKINGS,
          SETTINGS_SETACCESSES,
          VIRTUAL_ORGANIZATION_ADMIN,
        ]}
      >
        <MenuItem
          component={Link}
          dense={true}
          to="/dashboard/settings/accesses"
          selected={
            location.pathname.includes('/dashboard/settings/accesses')
          }
          classes={{ root: classes.leftButton }}
        >
          <div style={{
            fontWeight: location.pathname.includes('/dashboard/settings/accesses')
              ? 'bold'
              : 'normal',
          }}
          >
            {t_i18n('Security')}
          </div>
        </MenuItem>
      </Security>
      <Security needs={[SETTINGS]}>
        <MenuItem
          component={Link}
          dense={true}
          to="/dashboard/settings/customization"
          selected={
            location.pathname.includes('/dashboard/settings/customization')
          }
          classes={{ root: classes.leftButton }}
        >
          <div style={{
            fontWeight: location.pathname.includes('/dashboard/settings/customization')
              ? 'bold'
              : 'normal',
          }}
          >
            {t_i18n('Customization')}
          </div>
        </MenuItem>
      </Security>
      <Security needs={[SETTINGS_SETLABELS]}>
        <MenuItem
          component={Link}
          dense={true}
          to="/dashboard/settings/vocabularies"
          selected={
            location.pathname.includes('/dashboard/settings/vocabularies')
          }
          classes={{ root: classes.leftButton }}
        >
          <div style={{
            fontWeight: location.pathname.includes('/dashboard/settings/vocabularies')
              ? 'bold'
              : 'normal',
          }}
          >
            {t_i18n('Taxonomies')}
          </div>
        </MenuItem>
      </Security>
      <Security needs={[SETTINGS]}>
        <MenuItem
          component={Link}
          dense={true}
          to="/dashboard/settings/activity"
          selected={
            location.pathname.includes('/dashboard/settings/activity')
          }
          classes={{ root: classes.leftButton }}
        >
          <>
            <div style={{
              fontWeight: location.pathname.includes('/dashboard/settings/activity')
                ? 'bold'
                : 'normal',
            }}
            >
              {t_i18n('Activity')}
            </div>
            <EEChip feature={t_i18n('Activity')} clickable={false} />
          </>
        </MenuItem>
      </Security>
      <Security needs={[SETTINGS]}>
        <MenuItem
          component={Link}
          dense={true}
          to="/dashboard/settings/file_indexing"
          selected={
            location.pathname.includes('/dashboard/settings/file_indexing')
          }
          classes={{ root: classes.leftButton }}
        >
          <div style={{
            fontWeight: location.pathname.includes('/dashboard/settings/file_indexing')
              ? 'bold'
              : 'normal',
          }}
          >
            {t_i18n('File indexing')}
          </div>
          <EEChip feature={t_i18n('File indexing')} clickable={false} />
        </MenuItem>
      </Security>
    </MenuList>
  );
};

export default LeftMenuSettings;
