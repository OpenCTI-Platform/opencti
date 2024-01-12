import React, { FunctionComponent } from 'react';
import Drawer from '@components/common/drawer/Drawer';
import { QueryRenderer } from '../../../../relay/environment';
import StixDomainObjectsExportsContent, { stixDomainObjectsExportsContentQuery } from './StixDomainObjectsExportsContent';
import {
  StixDomainObjectsExportsContentRefetchQuery$data,
  StixDomainObjectsExportsContentRefetchQuery$variables,
} from './__generated__/StixDomainObjectsExportsContentRefetchQuery.graphql';
import { useFormatter } from '../../../../components/i18n';

interface StixDomainObjectsExportsProps {
  exportContext: { entity_id?: string; entity_type: string };
  paginationOptions: StixDomainObjectsExportsContentRefetchQuery$variables;
  open: boolean;
  handleToggle: () => void;
}

const StixDomainObjectsExports: FunctionComponent<
StixDomainObjectsExportsProps
> = ({ exportContext, paginationOptions, open, handleToggle }) => {
  const { t } = useFormatter();
  return (
    <Drawer
      open={open}
      onClose={handleToggle}
      title={t('Exports list')}
    >
      <QueryRenderer
        query={stixDomainObjectsExportsContentQuery}
        variables={{ count: 25, exportContext }}
        render={({
          props,
        }: {
          props: StixDomainObjectsExportsContentRefetchQuery$data;
        }) => (
          <StixDomainObjectsExportsContent
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

export default StixDomainObjectsExports;
