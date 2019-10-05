import React, { useEffect } from 'react';
import * as PropTypes from 'prop-types';
import { createRefetchContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { interval } from 'rxjs';
import FileLine from './FileLine';
import { FIVE_SECONDS } from '../../../../utils/Time';

const interval$ = interval(FIVE_SECONDS);

const FileExportViewerComponent = ({ entity, relay }) => {
  const { id, exportFiles } = entity;
  const { edges } = exportFiles;
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
      {edges.length ? edges.map((file, index) => <div style={{ marginLeft: -15 }} key={index}>
        <FileLine entityId={id} file={file.node}/>
      </div>) : <div style={{ padding: 10 }}>No file</div>}
  </React.Fragment>;
};

export const FileExportViewerRefetchQuery = graphql`
    query FileExportViewerRefetchQuery($id: String!) {
        stixDomainEntity(id: $id) {
            ...FileExportViewer_entity
        }
    }
`;

const FileExportViewer = createRefetchContainer(
  FileExportViewerComponent,
  {
    entity: graphql`
            fragment FileExportViewer_entity on StixDomainEntity {
                id
                exportFiles(first: 1000) @connection(key: "Pagination_exportFiles") {
                    edges {
                        node {
                            ...FileLine_file
                        }
                    }
                }
            }
        `,
  },
  FileExportViewerRefetchQuery,
);

FileExportViewer.propTypes = {
  entity: PropTypes.object,
};

export default FileExportViewer;
