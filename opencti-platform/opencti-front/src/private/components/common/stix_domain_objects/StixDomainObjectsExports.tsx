import React, { FunctionComponent } from 'react';
import Drawer from '@components/common/drawer/Drawer';
import { QueryRenderer } from '../../../../relay/environment';
import StixDomainObjectsExportsContent, { stixDomainObjectsExportsContentQuery } from './StixDomainObjectsExportsContent';
import { StixDomainObjectsExportsContentRefetchQuery$data, StixDomainObjectsExportsContentRefetchQuery$variables } from './__generated__/StixDomainObjectsExportsContentRefetchQuery.graphql';
import { useFormatter } from '../../../../components/i18n';

interface StixDomainObjectsExportsProps {
  exportEntityType: string;
  paginationOptions: StixDomainObjectsExportsContentRefetchQuery$variables;
  open: boolean;
  handleToggle: () => void;
  context: string;
}

const StixDomainObjectsExports: FunctionComponent<
StixDomainObjectsExportsProps
> = ({ exportEntityType, paginationOptions, open, handleToggle, context }) => {
  const { t } = useFormatter();
  return (
    <Drawer
      open={open}
      onClose={handleToggle}
      title={t('Exports list')}
    >
      <QueryRenderer
        query={stixDomainObjectsExportsContentQuery}
        variables={{ count: 25, type: exportEntityType, context }}
        render={({
          props,
        }: {
          props: StixDomainObjectsExportsContentRefetchQuery$data;
        }) => (
          <StixDomainObjectsExportsContent
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

export default StixDomainObjectsExports;
