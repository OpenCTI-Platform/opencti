import React from 'react';
import * as PropTypes from 'prop-types';
import Drawer from '../drawer/Drawer';
import { QueryRenderer } from '../../../../relay/environment';
import StixCoreObjectsExportsContent, { stixCoreObjectsExportsContentQuery } from './StixCoreObjectsExportsContent';
import { useFormatter } from '../../../../components/i18n';

const StixCoreObjectsExports = ({
  exportContext,
  paginationOptions,
  open,
  handleToggle,
  exportType,
}) => {
  const { t_i18n } = useFormatter();
  return (
    <Drawer
      open={open}
      title={t_i18n('Exports list')}
      onClose={handleToggle}
    >
      <QueryRenderer
        query={stixCoreObjectsExportsContentQuery}
        variables={{ count: 25, exportContext }}
        render={({ props }) => (
          <StixCoreObjectsExportsContent
            handleToggle={handleToggle}
            data={props}
            exportType={exportType}
            paginationOptions={paginationOptions}
            exportContext={exportContext}
            isOpen={open}
          />
        )}
      />
    </Drawer>
  );
};

StixCoreObjectsExports.propTypes = {
  exportContext: PropTypes.object,
  paginationOptions: PropTypes.object,
  open: PropTypes.bool,
  exportType: PropTypes.string,
  handleToggle: PropTypes.func,
};

export default StixCoreObjectsExports;
