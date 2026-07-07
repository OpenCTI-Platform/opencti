import { PlayCircleOutlined } from '@mui/icons-material';
import { Alert, CircularProgress, List, ListItem, ListItemIcon, ListItemText } from '@mui/material';
import React from 'react';
import Drawer from '@components/common/drawer/Drawer';
import ItemIcon from '../../../../components/ItemIcon';
import Security from '../../../../utils/Security';
import { AUTOMATION } from '../../../../utils/hooks/useGranted';
import IconButton from '@common/button/IconButton';
import Tooltip from '@mui/material/Tooltip';
import { useFormatter } from '../../../../components/i18n';
import type { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import useEnrollPlaybooks from './hooks/useEnrollPlaybooks';

interface Props {
  open: boolean;
  onClose: () => void;
  onLaunch: (playbookId: string, playbookName: string) => void;
  entityIds?: string[];
  isSelectAll?: boolean;
  filters?: FilterGroup | null;
  search?: string | null;
  excludedIds?: string[];
}

const EnrollPlaybookDrawer = ({ open, onClose, onLaunch, entityIds, isSelectAll, filters, search, excludedIds }: Props) => {
  const { t_i18n } = useFormatter();
  const { playbooks, loading } = useEnrollPlaybooks({ open, entityIds, isSelectAll, filters, search, excludedIds });

  return (
    <Drawer
      title={t_i18n('Enroll in playbook')}
      open={open}
      onClose={onClose}
    >
      <>
        <Alert severity="info" variant="outlined">
          {t_i18n('Listing playbooks with entry points manual or live trigger (events) and matching filters. Only the first 5000 entities have been checked for compatibility, any incompatible entities will not be processed by the selected playbook.')}
        </Alert>
        {loading ? (
          <div style={{ display: 'flex', justifyContent: 'center', marginTop: 20 }}>
            <CircularProgress />
          </div>
        ) : (
          <List>
            {playbooks.length > 0 ? (
              playbooks.map((playbook) => (
                <ListItem
                  key={playbook.value}
                  divider
                  secondaryAction={(
                    <Security needs={[AUTOMATION]}>
                      <Tooltip title={t_i18n('Enroll in this playbook')}>
                        <IconButton
                          onClick={() => onLaunch(playbook.value, playbook.label)}
                        >
                          <PlayCircleOutlined />
                        </IconButton>
                      </Tooltip>
                    </Security>
                  )}
                >
                  <ListItemIcon>
                    <ItemIcon type="Playbook" />
                  </ListItemIcon>
                  <ListItemText
                    primary={playbook.label}
                    secondary={playbook.description ?? ''}
                  />
                </ListItem>
              ))
            ) : (
              <div style={{ color: 'text.primary', fontSize: 15, textAlign: 'center', marginTop: 20 }}>
                {t_i18n('No playbook available')}
              </div>
            )}
          </List>
        )}
      </>
    </Drawer>
  );
};

export default EnrollPlaybookDrawer;
