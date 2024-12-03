import React from 'react';
import Breadcrumbs from '../../../components/Breadcrumbs';
import { useFormatter } from '../../../components/i18n';

const Management = () => {
  const { t_i18n } = useFormatter();

  return (
    <div data-testid='data-management-page'>
      <Breadcrumbs elements={[{ label: t_i18n('Data') }, { label: t_i18n('Management'), current: true }]}/>
      {/* {queryRef && ( */}
      {/*  <DataTable */}
      {/*    initialValues={initialValues} */}
      {/*    preloadedPaginationProps={preloadedPaginationProps} */}
      {/*    resolvePath={(data: EntitiesStixDomainObjectsLines_data$data) => data.stixDomainObjects?.edges?.map((n) => n?.node)} */}
      {/*    dataColumns={dataColumns} */}
      {/*    lineFragment={} */}
      {/*    exportContext={{ entity_type: 'Stix-Domain-Object' }} */}
      {/*    availableEntityTypes={['Stix-Domain-Object']} */}
      {/*  /> */}
      {/* )} */}
    </div>
  );
};

export default Management;
