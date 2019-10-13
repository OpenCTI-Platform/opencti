import React, { useEffect } from 'react';
import * as PropTypes from 'prop-types';
import { createRefetchContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { interval } from 'rxjs';
import FileLine from './FileLine';
import { TEN_SECONDS } from '../../../../utils/Time';

const interval$ = interval(TEN_SECONDS);

const FileImportViewerComponent = ({ entity, connectors, relay }) => {
  const { id, importFiles } = entity;
  const { edges } = importFiles;
  useEffect(() => {
    // Refresh the export viewer every interval
    const subscription = interval$.subscribe(() => {
      relay.refetch({ id });
    });
    return function cleanup() {
      subscription.unsubscribe();
    };
  });
  return <React.Fragment>
      {edges.length ? edges.map(file => <div style={{ marginLeft: -15 }} key={file.node.id}>
        <FileLine entityId={id} file={file.node}
                  connectors={connectors[file.node.metaData.mimetype]}/>
      </div>) : <div style={{ padding: 10 }}>No file</div>}
  </React.Fragment>;
};

const FileImportViewerRefetchQuery = graphql`
    query FileImportViewerRefetchQuery($id: String!) {
        stixDomainEntity(id: $id) {
            ...FileImportViewer_entity
        }
    }
`;

const FileImportViewer = createRefetchContainer(
  FileImportViewerComponent,
  {
    entity: graphql`
        fragment FileImportViewer_entity on StixDomainEntity {
            id
            importFiles(first: 1000) @connection(key: "Pagination_importFiles") {
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
    `,
  },
  FileImportViewerRefetchQuery,
);

FileImportViewer.propTypes = {
  entity: PropTypes.object,
  connectors: PropTypes.array,
};

export default FileImportViewer;
