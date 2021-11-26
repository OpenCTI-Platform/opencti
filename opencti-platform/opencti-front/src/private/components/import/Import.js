import React from 'react';
import * as PropTypes from 'prop-types';
import { QueryRenderer } from '../../../relay/environment';
import ImportContent, { importContentQuery } from './ImportContent';
import Loader from '../../../components/Loader';

const Import = () => (
  <QueryRenderer
    query={importContentQuery}
    variables={{}}
    render={({ props }) => {
      if (props) {
        return (
          <ImportContent
            connectorsImport={props.connectorsForImport}
            importFiles={props.importFiles}
            pendingFiles={props.pendingFiles}
          />
        );
      }
      return <Loader />;
    }}
  />
);

Import.propTypes = {
  children: PropTypes.node,
};

export default Import;
