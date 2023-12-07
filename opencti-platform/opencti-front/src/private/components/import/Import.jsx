import React from 'react';
import * as PropTypes from 'prop-types';
import { useNavigate } from 'react-router-dom-v5-compat';
import { QueryRenderer } from '../../../relay/environment';
import ImportContent, { importContentQuery } from './ImportContent';
import Loader from '../../../components/Loader';

const Import = () => {
  const navigate = useNavigate();
  return (
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
              navigate={navigate}
            />
          );
        }
        return <Loader/>;
      }}
    />
  );
};

Import.propTypes = {
  children: PropTypes.node,
};

export default Import;
