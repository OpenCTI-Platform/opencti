import React, { useEffect } from 'react';
import * as PropTypes from 'prop-types';
import { createRefetchContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { interval } from 'rxjs';
import FileLine from './FileLine';
import { FIVE_SECONDS } from '../../../../utils/Time';

/*
  componentDidMount() {
    this.subscription = interval$.subscribe(() => {
      this.props.relay.refetch({
        id: this.props.stixDomainEntity.id,
        types: ['stix2-bundle-simple', 'stix2-bundle-full'],
      });
    });
  }

  componentWillUnmount() {
    this.subscription.unsubscribe();
  }
 */
const interval$ = interval(FIVE_SECONDS);

const FileExportViewerComponent = ({ entity, relay }) => {
  const { internalId, exportFiles } = entity;
  const { edges } = exportFiles;
  useEffect(() => {
    const subscription = interval$.subscribe(() => {
      relay.refetch({ id: internalId });
    });
    // Specify how to clean up after this effect:
    return function cleanup() {
      subscription.unsubscribe();
    };
  });
  return <React.Fragment>
      {edges.length ? edges.map((file, index) => <div style={{ marginLeft: -15 }} key={index}>
        <FileLine entityId={internalId} file={file.node}/>
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
                internalId: internal_id
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
