import List from '@mui/material/List';
import { ListItemButton } from '@mui/material';
import { Link } from 'react-router-dom';
import Tooltip from '@mui/material/Tooltip';
import ListItemIcon from '@mui/material/ListItemIcon';
import { Extension } from '@mui/icons-material';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import Paper from '@mui/material/Paper';
import React from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { truncate } from '../../../../utils/String';
import { useFormatter } from '../../../../components/i18n';
import { ImportContentQuery$data } from './__generated__/ImportContentQuery.graphql';

const useStyles = makeStyles(() => ({
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

const ImportConnectors = ({ connectorsImport }: { connectorsImport: ImportContentQuery$data['connectorsForImport'] }) => {
  const classes = useStyles();
  const { nsdt, t_i18n } = useFormatter();
  const connectors = connectorsImport.filter((n) => !n.only_contextual); // Can be null but not empty
  return (
    <Paper
      classes={{ root: classes.paper }}
      variant="outlined"
      style={{ marginTop: 12 }}
      className={'paper-for-grid'}
    >
      {connectors.length ? (
        <List>
          {connectors.map((connector) => {
            const connectorScope = connector.connector_scope.join(',');
            return (
              <ListItemButton
                component={Link}
                to={`/dashboard/data/ingestion/connectors/${connector.id}`}
                key={connector.id}
                dense={true}
                divider={true}
                classes={{ root: classes.item }}
              >
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
                    <Extension/>
                  </ListItemIcon>
                </Tooltip>
                <Tooltip title={connectorScope}>
                  <ListItemText
                    primary={connector.name}
                    secondary={truncate(connectorScope, 30)}
                  />
                </Tooltip>
                {connector.updated_at && (<ListItemSecondaryAction>
                  <ListItemText primary={nsdt(connector.updated_at)}/>
                </ListItemSecondaryAction>)}
              </ListItemButton>
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
  );
};

export default ImportConnectors;
