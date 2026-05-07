import { graphql } from 'react-relay';
import { fetchQuery } from '../../../../../../relay/environment';
import { getDashboardExportHandler } from '../../../../../../components/dashboard/import-export/dashboard-export-utils';
import type { ExportableDashboardLike } from '../../../../../../components/dashboard/dashboard-types';
import type { customViewExportUtils_Query$data } from './__generated__/customViewExportUtils_Query.graphql';

const customViewExportQuery = graphql`
  query customViewExportUtils_Query($id: ID!) {
    customView(id: $id) {
      toConfigurationExport
    }
  }
`;

const onExport = async (id: string) => {
  const data = await fetchQuery(customViewExportQuery, { id })
    .toPromise();
  const result = data as customViewExportUtils_Query$data;
  const exportString = result.customView?.toConfigurationExport;
  if (!exportString) {
    return null;
  }
  return exportString;
};

export const getCustomViewExportHandler = (customView: ExportableDashboardLike) => {
  return getDashboardExportHandler({ onExport, configType: 'custom-view', entity: customView });
};
