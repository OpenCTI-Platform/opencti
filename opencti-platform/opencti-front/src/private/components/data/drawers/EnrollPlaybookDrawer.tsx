import { PlayCircleOutlined } from '@mui/icons-material';
import { Alert, List, ListItem, ListItemIcon, ListItemText } from '@mui/material';
import { graphql } from 'react-relay';
import React, { useEffect, useState } from 'react';
import Drawer from '@components/common/drawer/Drawer';
import ItemIcon from '../../../../components/ItemIcon';
import { fetchQuery } from '../../../../relay/environment';
import Security from '../../../../utils/Security';
import { AUTOMATION } from '../../../../utils/hooks/useGranted';
import IconButton from '@common/button/IconButton';
import Tooltip from '@mui/material/Tooltip';
import { useFormatter } from '../../../../components/i18n';
import { EnrollPlaybookDrawerQuery$data } from '@components/data/drawers/__generated__/EnrollPlaybookDrawerQuery.graphql';

const toolBarPlaybooksQuery = graphql`
  query EnrollPlaybookDrawerQuery {
    playbooks(first: 500, orderBy: name, orderMode: asc) {
      edges {
        node {
          id
          name
          description
          playbook_running
        }
      }
    }
  }
`;

interface Playbook {
  label: string;
  value: string;
  description: string | null | undefined;
}

interface Props {
  open: boolean;
  onClose: () => void;
  onLaunch: (playbookId: string, playbookName: string) => void;
}

const EnrollPlaybookDrawer = ({ open, onClose, onLaunch }: Props) => {
  const { t_i18n } = useFormatter();
  const [playbooks, setPlaybooks] = useState<Playbook[]>([]);

  useEffect(() => {
    if (!open) return;
    fetchQuery(toolBarPlaybooksQuery)
      .toPromise()
      .then((playbooks) => {
        const data = playbooks as EnrollPlaybookDrawerQuery$data;
        const fetched = (data?.playbooks?.edges ?? [])
          .map((edge) => edge?.node)
          .filter((p): p is NonNullable<typeof p> => Boolean(p && p.playbook_running))
          .map((p) => ({
            label: p.name,
            value: p.id,
            description: p.description,
          }))
          .sort((a, b) => a.label.localeCompare(b.label));
        setPlaybooks(fetched);
      });
  }, [open]);

  return (
    <Drawer
      title={t_i18n('Enroll in playbook')}
      open={open}
      onClose={onClose}
    >
      <>
        <Alert severity="info" variant="outlined">
          {t_i18n('Select a playbook to enroll the selected entities.')}
        </Alert>
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
      </>
    </Drawer>
  );
};

export default EnrollPlaybookDrawer;
