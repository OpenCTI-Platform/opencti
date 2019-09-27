import React from 'react';
import * as PropTypes from 'prop-types';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import FileLine from './FileLine';

const FileImportViewerComponent = ({ entity }) => {
  const { id, importFiles } = entity;
  const { edges } = importFiles;
  return <React.Fragment>
      {edges.length ? edges.map((file, index) => <div style={{ marginLeft: -15 }} key={index}>
        <FileLine entityId={id} file={file.node}/>
      </div>) : <div style={{ padding: 10 }}>No file</div>}
  </React.Fragment>;
};

const FileImportViewer = createFragmentContainer(FileImportViewerComponent, {
  entity: graphql`
        fragment FileImportViewer_entity on StixDomainEntity {
            id
            importFiles(first: 1000) @connection(key: "Pagination_importFiles") {
                edges {
                    node {
                        ...FileLine_file     
                    }
                }
            }
        }
    `,
});

FileImportViewer.propTypes = {
  entity: PropTypes.object,
};

export default FileImportViewer;
