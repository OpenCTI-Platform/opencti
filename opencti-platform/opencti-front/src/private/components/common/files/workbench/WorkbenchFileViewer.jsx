import React, { useEffect, useState } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createRefetchContainer, graphql } from 'react-relay';
import { interval } from 'rxjs';
import Grid from '@mui/material/Grid';
import withStyles from '@mui/styles/withStyles';
import List from '@mui/material/List';
import IconButton from '@common/button/IconButton';
import { Add } from '@mui/icons-material';
import Card from '@common/card/Card';
import { TEN_SECONDS } from '../../../../../utils/Time';
import inject18n from '../../../../../components/i18n';
import WorkbenchFileLine from './WorkbenchFileLine';
import WorkbenchFileCreator from './WorkbenchFileCreator';
import { KNOWLEDGE_KNASKIMPORT } from '../../../../../utils/hooks/useGranted';
import Security from '../../../../../utils/Security';
import useDraftContext from '../../../../../utils/hooks/useDraftContext';

const interval$ = interval(TEN_SECONDS);

const styles = () => ({
  paper: {
    padding: '10px 15px 10px 15px',
    marginTop: -2,
    borderRadius: 4,
  },
});

const WorkbenchFileViewerBase = ({
  entity,
  handleOpenImport,
  connectors,
  relay,
  t,
  classes,
}) => {
  const { id, pendingFiles } = entity;
  const { edges } = pendingFiles;
  const [openCreate, setOpenCreate] = useState(false);
  const draftContext = useDraftContext();

  useEffect(() => {
    // Refresh the export viewer every interval
    const subscription = interval$.subscribe(() => {
      relay.refetch({ id });
    });
    return function cleanup() {
      subscription.unsubscribe();
    };
  });

  const onCreateWorkbenchCompleted = () => {
    relay.refetch({ id });
  };

  return (
    <Grid item xs={6}>
      <div style={{ height: '100%' }}>
        <Card
          title={t('Analyst workbenches')}
          action={(
            <Security needs={[KNOWLEDGE_KNASKIMPORT]} hasAccess={!draftContext}>
              <IconButton
                color="primary"
                aria-label="Add"
                onClick={() => setOpenCreate(true)}
                classes={{ root: classes.createButton }}
                size="small"
              >
                <Add fontSize="small" />
              </IconButton>
            </Security>
          )}
        >
          {edges.length ? (
            <List>
              {edges.map((file) => (
                <WorkbenchFileLine
                  key={file.node.id}
                  dense={true}
                  file={file.node}
                  connectors={
                    connectors && connectors[file.node.metaData.mimetype]
                  }
                  handleOpenImport={handleOpenImport}
                />
              ))}
            </List>
          ) : (
            <div style={{ display: 'table', height: '100%', width: '100%' }}>
              <span
                style={{
                  display: 'table-cell',
                  verticalAlign: 'middle',
                  textAlign: 'center',
                }}
              >
                {t('No file for the moment')}
              </span>
            </div>
          )}
        </Card>
        <WorkbenchFileCreator
          handleCloseCreate={() => setOpenCreate(false)}
          openCreate={openCreate}
          onCompleted={onCreateWorkbenchCompleted}
          entity={entity}
        />
      </div>
    </Grid>
  );
};

const WorkbenchFileViewerComponent = compose(
  inject18n,
  withStyles(styles),
)(WorkbenchFileViewerBase);

const WorkbenchFileViewerRefetchQuery = graphql`
  query WorkbenchFileViewerRefetchQuery($id: String!) {
    stixCoreObject(id: $id) {
      ...WorkbenchFileViewer_entity
    }
  }
`;

const WorkbenchFileViewer = createRefetchContainer(
  WorkbenchFileViewerComponent,
  {
    entity: graphql`
      fragment WorkbenchFileViewer_entity on StixCoreObject {
        id
        entity_type
        pendingFiles(first: 500) @connection(key: "Pagination_pendingFiles") {
          edges {
            node {
              id
              ...ImportWorkbenchesContentFileLine_file
              metaData {
                mimetype
              }
            }
          }
        }
      }
    `,
  },
  WorkbenchFileViewerRefetchQuery,
);

WorkbenchFileViewer.propTypes = {
  entity: PropTypes.object,
  disableImport: PropTypes.bool,
  connectors: PropTypes.object,
};

export default WorkbenchFileViewer;
