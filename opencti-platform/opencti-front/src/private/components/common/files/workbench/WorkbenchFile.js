import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql } from 'react-relay';
import { withRouter } from 'react-router-dom';
import * as R from 'ramda';
import { QueryRenderer } from '../../../../../relay/environment';
import WorkbenchFileContent from './WorkbenchFileContent';
import Loader from '../../../../../components/Loader';
import { fromB64 } from '../../../../../utils/String';

const workbenchFileQuery = graphql`
  query WorkbenchFileQuery($id: String!) {
    stixDomainObjectTypes: subTypes(type: "Stix-Domain-Object") {
      edges {
        node {
          id
          label
        }
      }
    }
    observableTypes: subTypes(type: "Stix-Cyber-Observable") {
      edges {
        node {
          id
          label
        }
      }
    }
    connectorsForImport {
      ...WorkbenchFileContent_connectorsImport
    }
    file(id: $id) {
      ...WorkbenchFileContent_file
    }
  }
`;

class WorkbenchFile extends Component {
  render() {
    const {
      match: {
        params: { fileId },
      },
    } = this.props;
    const decodedFileId = fromB64(fileId);
    return (
      <QueryRenderer
        query={workbenchFileQuery}
        variables={{ id: decodedFileId }}
        render={({ props }) => {
          if (props && props.file) {
            return (
              <WorkbenchFileContent
                file={props.file}
                connectorsImport={props.connectorsForImport}
                stixDomainObjectTypes={props.stixDomainObjectTypes}
                observableTypes={props.observableTypes}
              />
            );
          }
          return <Loader />;
        }}
      />
    );
  }
}

WorkbenchFile.propTypes = {
  children: PropTypes.node,
};

export default R.compose(withRouter)(WorkbenchFile);
