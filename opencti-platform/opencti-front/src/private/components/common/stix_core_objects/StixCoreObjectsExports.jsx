import React from 'react';
import Drawer from '../drawer/Drawer';

import { QueryRenderer } from '../../../../relay/environment';
import StixCoreObjectsExportsContent, { stixCoreObjectsExportsContentQuery } from './StixCoreObjectsExportsContent';
import { useFormatter } from '../../../../components/i18n';

const StixCoreObjectsExports = ({
  exportContext,
  paginationOptions,
  open,
  handleToggle,
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
            paginationOptions={paginationOptions}
            exportContext={exportContext}
            isOpen={open}
          />
        )}
      />
    </Drawer>
  );
};

export default StixCoreObjectsExports;
