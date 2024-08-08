import Paper from '@mui/material/Paper';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import WorkbenchFileLine from '@components/common/files/workbench/WorkbenchFileLine';
import React, { FunctionComponent } from 'react';
import { ImportContentContainer_connectorsImport$data } from '@components/data/import/__generated__/ImportContentContainer_connectorsImport.graphql';
import { ImportContentQuery$data } from '@components/import/__generated__/ImportContentQuery.graphql';
import makeStyles from '@mui/styles/makeStyles';
import { scopesConn } from '@components/common/files/FileManager';
import ImportMenu from '@components/data/ImportMenu';
import { useFormatter } from '../../../../components/i18n';

interface ImportWorkbenchesProps {
  pendingFiles: ImportContentQuery$data['pendingFiles'],
  connectors: ImportContentContainer_connectorsImport$data,
  handleOpenValidate: (file) => void,
}

const useStyles = makeStyles(() => ({
  paper: {
    padding: '10px 15px 10px 15px',
    borderRadius: 4,
    marginTop: 2,
  },
  itemHead: {
    paddingLeft: 10,
    textTransform: 'uppercase',
  },
}));

const inlineStylesHeaders = {
  iconSort: {
    position: 'absolute',
    margin: '0 0 0 5px',
    padding: 0,
    top: '0px',
  },
  name: {
    float: 'left',
    width: '35%',
    fontSize: 12,
    fontWeight: '700',
  },
  creator_name: {
    float: 'left',
    width: '20%',
    fontSize: 12,
    fontWeight: '700',
  },
  labels: {
    float: 'left',
    width: '20%',
    fontSize: 12,
    fontWeight: '700',
  },
  lastModified: {
    float: 'left',
    width: '20%',
    fontSize: 12,
    fontWeight: '700',
  },
};

const ImportWorkbenches: FunctionComponent<ImportWorkbenchesProps> = ({
  pendingFiles,
  connectors,
  handleOpenValidate,
}) => {
  const pendingFilesEdges = pendingFiles?.edges ?? [];
  const importConnsPerFormat = scopesConn(connectors);

  const { t_i18n } = useFormatter();
  const classes = useStyles();

  const header = (field: string, label: string) => {
    return (
      <div style={inlineStylesHeaders[field]}>
        <span>{t_i18n(label)}</span>
      </div>
    );
  };

  return (
    <>
      <div style={{ height: '100%' }} className="break">
        <ImportMenu />
        <Paper classes={{ root: classes.paper }} variant="outlined">
          <List>
            <ListItem
              classes={{ root: classes.itemHead }}
              divider={false}
              style={{ paddingTop: 0 }}
            >
              <ListItemIcon>
                <span
                  style={{
                    padding: '0 8px 0 8px',
                    fontWeight: 700,
                    fontSize: 12,
                  }}
                >
                        &nbsp;
                </span>
              </ListItemIcon>
              <ListItemText
                primary={
                  <div>
                    {header('name', 'Name')}
                    {header('creator_name', 'Creator')}
                    {header('labels', 'Labels')}
                    {header('lastModified', 'Modification date')}
                  </div>
                }
              />
              <ListItemSecondaryAction style={{ width: 96 }}> &nbsp; </ListItemSecondaryAction>
            </ListItem>
            {pendingFilesEdges.map((file) => (
              <WorkbenchFileLine
                key={file.node.id}
                file={file.node}
                connectors={importConnsPerFormat[file.node.metaData.mimetype]}
                handleOpenImport={handleOpenValidate}
              />
            ))}
          </List>
        </Paper>
      </div>
    </>
  );
};

export default ImportWorkbenches;
