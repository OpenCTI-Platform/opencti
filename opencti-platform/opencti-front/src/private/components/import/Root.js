import React, { useEffect } from 'react';
import Typography from '@material-ui/core/Typography';
import Tooltip from '@material-ui/core/Tooltip';
import Badge from '@material-ui/core/Badge';
import {
  compose, head, last, map, toPairs, filter,
} from 'ramda';
import { ShutterSpeed } from '@material-ui/icons';
import Paper from '@material-ui/core/Paper';
import { withStyles } from '@material-ui/core';
import { createRefetchContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { interval } from 'rxjs';
import FileUploader from '../common/files/FileUploader';
import inject18n from '../../../components/i18n';
import { QueryRenderer } from '../../../relay/environment';
import FileLine from '../common/files/FileLine';
import { scopesConn } from '../common/files/FileManager';
import { TEN_SECONDS } from '../../../utils/Time';
import Loader from '../../Loader';

const interval$ = interval(TEN_SECONDS);

const styles = () => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
  paper: {
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
});

export const RootImportQuery = graphql`
    query RootImportQuery {
        connectorsForImport {
            ...Root_connectorsImport
        }
        importFiles(first: 1000) @connection(key: "Pagination_global_importFiles") {
            edges {
                node {
                    id
                    ...FileLine_file
                    metaData {
                        mimetype
                    }
                }
            }
        }
    }
`;

const ImportRoot = ({
  t, classes, connectorsImport, importFiles, relay,
}) => {
  useEffect(() => {
    // Refresh the export viewer every interval
    const subscription = interval$.subscribe(() => {
      relay.refetch();
    });
    return function cleanup() {
      subscription.unsubscribe();
    };
  });
  const { edges } = importFiles;
  const importConnsPerFormat = scopesConn(connectorsImport);
  const onUploadSuccess = () => relay.refetch();
  const isImportActive = () => filter(x => x.active, connectorsImport).length > 0;
  const importConnsTooltip = () => {
    const connsPair = toPairs(importConnsPerFormat);
    const data = map((x) => {
      const associateConnectors = map(s => `${s.data.name} ${s.data.active ? '(active)' : '(disconnected)'}`, last(x));
      return `${head(x)} [ ${associateConnectors.join(', ')} ]`;
    }, connsPair);
    return data.join('\r\n');
  };
  return <React.Fragment>
        <div>
            <div style={{ float: 'left' }}>
                <Typography variant="h2" style={{ paddingTop: 15 }} gutterBottom={true}>
                    {t('Uploaded / Imported files')}
                </Typography>
            </div>
            <div style={{ float: 'right' }}>
                <Tooltip title={importConnsTooltip()} aria-label={importConnsTooltip()}>
                    <Badge color={isImportActive() ? 'primary' : 'secondary'}
                           badgeContent={connectorsImport.length}
                           anchorOrigin={{ horizontal: 'right', vertical: 'top' }}
                           style={{ marginRight: 15 }}>
                        <ShutterSpeed/>
                    </Badge>
                </Tooltip>
                <FileUploader onUploadSuccess={onUploadSuccess}/>
            </div>
            <div className="clearfix" />
        </div>
        <Paper classes={{ root: classes.paper }} elevation={2}>
            {edges.length ? edges.map(file => <div style={{ marginLeft: -15 }} key={file.node.id}>
                <FileLine file={file.node}
                          connectors={importConnsPerFormat[file.node.metaData.mimetype]}/>
            </div>) : <div style={{ padding: 10 }}>No file</div>}
        </Paper>
    </React.Fragment>;
};

const ImportRootCompose = compose(
  inject18n,
  withStyles(styles),
)(ImportRoot);

const ImportRootFragment = createRefetchContainer(
  ImportRootCompose, {
    connectorsImport: graphql`
        fragment Root_connectorsImport on Connector @relay(plural: true) {
            id
            name
            active
            connector_scope
            updated_at
        }
    `,
  },
  RootImportQuery,
);

export const ImportRootComponent = () => <QueryRenderer
    query={RootImportQuery}
    variables={{}}
    render={({ props }) => {
      if (props) {
        return <ImportRootFragment connectorsImport={props.connectorsForImport}
                    importFiles={props.importFiles}/>;
      }
      return <Loader/>;
    }}
/>;

export default ImportRootComponent;
