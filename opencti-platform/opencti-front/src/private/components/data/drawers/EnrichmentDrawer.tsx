import React, { useEffect, useState } from 'react';
import Alert from '@mui/material/Alert';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Typography from '@mui/material/Typography';
import { CloudRefreshOutline } from 'mdi-material-ui';
import { Switch } from '@filigran/design-system';
import Button from '@common/button/Button';
import Drawer from '@components/common/drawer/Drawer';
import FormButtonContainer from '../../../../components/common/form/FormButtonContainer';
import { useFormatter } from '../../../../components/i18n';

export interface EnrichmentConnector {
  id: string;
  name: string;
}

interface EnrichmentDrawerProps {
  open: boolean;
  onClose: () => void;
  connectors: EnrichmentConnector[];
  onLaunch: (connectorIds: string[]) => void;
}

const EnrichmentDrawer = ({ open, onClose, connectors, onLaunch }: EnrichmentDrawerProps) => {
  const { t_i18n } = useFormatter();
  const [selectedIds, setSelectedIds] = useState<string[]>([]);

  // Every opening starts with no connector selected
  useEffect(() => {
    if (open) setSelectedIds([]);
  }, [open]);

  const toggleConnector = (connectorId: string) => {
    setSelectedIds((ids) => (ids.includes(connectorId)
      ? ids.filter((id) => id !== connectorId)
      : [...ids, connectorId]));
  };

  return (
    <Drawer
      title={t_i18n('Entity enrichment')}
      open={open}
      onClose={onClose}
    >
      <div>
        <Typography
          variant="h4"
          gutterBottom={true}
          style={{ marginTop: 20 }}
        >
          {t_i18n('Selected connectors')}
        </Typography>
        <List>
          {connectors.length === 0 && (
            <Alert severity="warning">
              {t_i18n('No connector available for the selected entities.')}
            </Alert>
          )}
          {connectors.map((connector) => (
            <ListItem
              key={connector.id}
              dense={true}
              divider={true}
              secondaryAction={(
                <Switch
                  checked={selectedIds.includes(connector.id)}
                  onCheckedChange={() => toggleConnector(connector.id)}
                  aria-label={connector.name}
                />
              )}
            >
              <ListItemIcon>
                <CloudRefreshOutline />
              </ListItemIcon>
              <ListItemText primary={connector.name} />
            </ListItem>
          ))}
        </List>
        <FormButtonContainer>
          <Button
            disabled={connectors.length === 0 || selectedIds.length === 0}
            onClick={() => onLaunch(selectedIds)}
          >
            {t_i18n('Enrich')}
          </Button>
        </FormButtonContainer>
      </div>
    </Drawer>
  );
};

export default EnrichmentDrawer;
