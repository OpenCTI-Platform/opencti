import React from 'react';
import Drawer, { DrawerVariant } from '../drawer/Drawer';

import { QueryRenderer } from '../../../../relay/environment';
import StixCoreObjectsExportsContent, { stixCoreObjectsExportsContentQuery } from './StixCoreObjectsExportsContent';
import { useFormatter } from '../../../../components/i18n';

const StixCoreObjectsExports = ({
  exportEntityType,
  paginationOptions,
  open,
  handleToggle,
  context,
}) => {
  const { t } = useFormatter();
  return (
    <Drawer
      variant={DrawerVariant.createWithPanel}
      open={open}
      title={t('Exports list')}
      onClose={handleToggle}
    >
      <QueryRenderer
        query={stixCoreObjectsExportsContentQuery}
        variables={{ count: 25, type: exportEntityType, context }}
        render={({ props }) => (
          <StixCoreObjectsExportsContent
            handleToggle={handleToggle}
            data={props}
            paginationOptions={paginationOptions}
            exportEntityType={exportEntityType}
            isOpen={open}
            context={context}
          />
        )}
      />
    </Drawer>
  );
};

export default StixCoreObjectsExports;
