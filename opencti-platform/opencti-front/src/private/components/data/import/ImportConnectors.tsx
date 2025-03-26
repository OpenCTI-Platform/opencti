import React from 'react';
import { List, ListItemButton, ListItemText, ListItemIcon, ListItem } from '@mui/material';
import { Link } from 'react-router-dom';
import Tooltip from '@mui/material/Tooltip';
import { Extension } from '@mui/icons-material';
import Paper from '@mui/material/Paper';
import makeStyles from '@mui/styles/makeStyles';
import ImportMenu from '@components/data/ImportMenu';
import { truncate } from '../../../../utils/String';
import { useFormatter } from '../../../../components/i18n';
import { ImportContentContainer_connectorsImport$data } from './__generated__/ImportContentContainer_connectorsImport.graphql';

const useStyles = makeStyles(() => ({
  container: {
    padding: '0 200px 50px 0',
  },
  paper: {
    padding: '10px 15px 10px 15px',
    borderRadius: 4,
    marginTop: 2,
  },
  item: {
    paddingLeft: 10,
    height: 50,
  },
}));

const ImportConnectors = ({ connectors }: { connectors: ImportContentContainer_connectorsImport$data }) => {
  const classes = useStyles();
  const { nsdt, t_i18n } = useFormatter();
  return (
    <div className={classes.container}>
      <ImportMenu />
      <Paper
        classes={{ root: classes.paper }}
        variant="outlined"
        style={{ marginTop: 12 }}
        className={'paper-for-grid'}
      >
        {connectors.length ? (
          <List>
            {connectors.map((connector) => {
              const connectorScope = connector.connector_scope?.join(',');
              return (
                <ListItem
                  key={connector.id}
                  dense
                  divider
                  disablePadding
                  classes={{ root: classes.item }}
                  secondaryAction={connector.updated_at && (<ListItemText primary={nsdt(connector.updated_at)} />)}
                >
                  <ListItemButton component={Link} to={`/dashboard/data/ingestion/connectors/${connector.id}`}>
                    <Tooltip
                      title={
                      connector.active
                        ? t_i18n('This connector is active')
                        : t_i18n('This connector is disconnected')
                    }
                    >
                      <ListItemIcon
                        style={{
                          color: connector.active ? '#4caf50' : '#f44336',
                        }}
                      >
                        <Extension />
                      </ListItemIcon>
                    </Tooltip>
                    <Tooltip title={connectorScope}>
                      <ListItemText primary={connector.name} secondary={truncate(connectorScope, 300)} />
                    </Tooltip>
                  </ListItemButton>
                </ListItem>
              );
            })}
          </List>
        ) : (
          <div
            style={{ display: 'table', height: '100%', width: '100%' }}
          >
            <span
              style={{
                display: 'table-cell',
                verticalAlign: 'middle',
                textAlign: 'center',
              }}
            >
              {t_i18n('No enrichment connectors on this platform')}
            </span>
          </div>
        )}
      </Paper>
    </div>
  );
};

export default ImportConnectors;
