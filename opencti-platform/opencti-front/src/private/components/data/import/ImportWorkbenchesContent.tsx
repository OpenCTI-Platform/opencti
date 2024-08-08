import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { scopesConn } from '@components/common/files/FileManager';
import React, { FunctionComponent, useState } from 'react';
import ImportMenu from '@components/data/ImportMenu';
import Paper from '@mui/material/Paper';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import WorkbenchFileLine from '@components/common/files/workbench/WorkbenchFileLine';
import WorkbenchFileCreator from '@components/common/files/workbench/WorkbenchFileCreator';
import Fab from '@mui/material/Fab';
import { Add } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import { ImportContentContainer_connectorsImport$data } from '@components/data/import/__generated__/ImportContentContainer_connectorsImport.graphql';
import { ImportWorkbenchesContentQuery } from '@components/data/import/__generated__/ImportWorkbenchesContentQuery.graphql';
import { useFormatter } from '../../../../components/i18n';

export const importWorkbenchesContentQuery = graphql`
  query ImportWorkbenchesContentQuery {
      pendingFiles(first: 500)
      @connection(key: "Pagination_global_pendingFiles") {
          edges {
              node {
                  id
                  ...WorkbenchFileLine_file
                  metaData {
                      mimetype
                  }
              }
          }
      }
  }
`;

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
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 230,
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

interface ImportWorkbenchesContentProps {
  connectors: ImportContentContainer_connectorsImport$data,
  queryRef: PreloadedQuery<ImportWorkbenchesContentQuery>,
}

const ImportWorkbenchesContent: FunctionComponent<ImportWorkbenchesContentProps> = ({ connectors, queryRef }) => {
  const data = usePreloadedQuery(importWorkbenchesContentQuery, queryRef);
  const pendingFilesEdges = data.pendingFiles?.edges ?? [];
  const importConnsPerFormat = scopesConn(connectors);

  const { t_i18n } = useFormatter();
  const classes = useStyles();

  const [displayCreate, setDisplayCreate] = useState(false);

  const header = (field: string, label: string) => {
    return (
      <div style={inlineStylesHeaders[field]}>
        <span>{t_i18n(label)}</span>
      </div>
    );
  };

  const handleOpenCreate = () => {
    setDisplayCreate(true);
  };

  const handleCloseCreate = () => {
    setDisplayCreate(false);
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
              />
            ))}
          </List>
        </Paper>
      </div>
      <WorkbenchFileCreator
        handleCloseCreate={handleCloseCreate}
        openCreate={displayCreate}
        onCompleted={undefined}
      />
      <Fab
        onClick={handleOpenCreate}
        color="primary"
        aria-label="Add"
        className={classes.createButton}
      >
        <Add />
      </Fab>
    </>
  );
};

export default ImportWorkbenchesContent;
