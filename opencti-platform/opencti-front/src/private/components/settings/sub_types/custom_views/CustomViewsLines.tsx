import React, { FunctionComponent } from 'react';
import DataTableWithoutFragment from '../../../../../components/dataGrid/DataTableWithoutFragment';
import { DataTableVariant } from '../../../../../components/dataGrid/dataTableTypes';
import { CustomViewsGrid_customViews$data } from '@components/settings/sub_types/custom_views/__generated__/CustomViewsGrid_customViews.graphql';
import { CustomViewType } from '@components/settings/sub_types/custom_views/CustomViewsGrid';

interface CustomViewsLinesProps {
  customViews: CustomViewsGrid_customViews$data['customViews'];
  dataTableRef?: HTMLDivElement | null;
  onUpdate?: (t: CustomViewType) => void;
  entitySettingId?: string;
  targetType?: string;
}

const CustomViewsLines: FunctionComponent<CustomViewsLinesProps> = ({
  customViews,
  dataTableRef,
  targetType,
}) => {
  const dataColumns = {
    name: { percentWidth: 41, isSortable: false },
    description: { percentWidth: 41, isSortable: false },
  };

  return (
    <DataTableWithoutFragment
      dataColumns={dataColumns}
      storageKey={`custom-views-${targetType}`}
      globalCount={customViews?.edges.length ?? 0}
      data={(customViews?.edges ?? []).map((e) => e.node)}
      rootRef={dataTableRef ?? undefined}
      variant={DataTableVariant.inline}
    />
  );
};

export default CustomViewsLines;
