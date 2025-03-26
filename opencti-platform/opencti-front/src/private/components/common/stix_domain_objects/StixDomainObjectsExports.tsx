import React, { FunctionComponent } from 'react';
import Drawer from '@components/common/drawer/Drawer';
import { QueryRenderer } from '../../../../relay/environment';
import StixDomainObjectsExportsContent, { stixDomainObjectsExportsContentQuery } from './StixDomainObjectsExportsContent';
import {
  StixDomainObjectsExportsContentRefetchQuery$data,
  StixDomainObjectsExportsContentRefetchQuery$variables,
} from './__generated__/StixDomainObjectsExportsContentRefetchQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import { ExportContext } from '../../../../utils/ExportContextProvider';
import { addFilter, emptyFilterGroup } from '../../../../utils/filters/filtersUtils';

interface StixDomainObjectsExportsProps {
  exportContext: { entity_id?: string; entity_type: string };
  paginationOptions: StixDomainObjectsExportsContentRefetchQuery$variables;
  open: boolean;
  handleToggle: () => void;
}

const StixDomainObjectsExports: FunctionComponent<
StixDomainObjectsExportsProps
> = ({ exportContext, paginationOptions, open, handleToggle }) => {
  const { t_i18n } = useFormatter();
  return (
    <ExportContext.Consumer>
      {({ selectedIds }) => {
        let tempSelectedIds = selectedIds;
        if (tempSelectedIds === undefined || tempSelectedIds === null || tempSelectedIds.length === 0) {
          tempSelectedIds = [''];
        }

        const filters = addFilter(emptyFilterGroup, 'id', tempSelectedIds);

        return (
          <Drawer
            open={open}
            onClose={handleToggle}
            title={t_i18n('Exports list')}
          >
            <QueryRenderer
              query={stixDomainObjectsExportsContentQuery}
              variables={{
                count: 25,
                exportContext,
                filters,
              }}
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
      }}
    </ExportContext.Consumer>
  );
};

export default StixDomainObjectsExports;
