import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { withRouter } from 'react-router-dom';
import * as R from 'ramda';
import { QueryRenderer } from '../../../relay/environment';
import PendingFileContent from './PendingFileContent';
import Loader from '../../../components/Loader';

const pendingFileQuery = graphql`
  query PendingFileQuery($id: String!) {
    connectorsForImport {
      ...PendingFileContent_connectorsImport
    }
    file(id: $id) {
      ...PendingFileContent_file
    }
  }
`;

class PendingFile extends Component {
  render() {
    const {
      match: {
        params: { fileId },
      },
    } = this.props;
    const decodedFileId = Buffer.from(fileId, 'base64').toString('binary');
    return (
      <QueryRenderer
        query={pendingFileQuery}
        variables={{ id: decodedFileId }}
        render={({ props }) => {
          if (props) {
            return (
              <PendingFileContent
                file={props.file}
                connectorsImport={props.connectorsForImport}
              />
            );
          }
          return <Loader />;
        }}
      />
    );
  }
}

PendingFile.propTypes = {
  children: PropTypes.node,
};

export default R.compose(withRouter)(PendingFile);
