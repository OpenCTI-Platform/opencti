import { stixCoreObjectsListQuery } from '@components/common/stix_core_objects/StixCoreObjectsList';
import React from 'react';
import { StixCoreObjectsListQuery } from '@components/common/stix_core_objects/__generated__/StixCoreObjectsListQuery.graphql';
import { renderToString } from 'react-dom/server';
import { IntlProvider } from 'react-intl';
import { buildFiltersAndOptionsForTemplateWidgets } from '../../../filters/filtersUtils';
import type { Widget } from '../../../widget/widget';
import { fetchQuery } from '../../../../relay/environment';
import WidgetListCoreObjects from '../../../../components/dashboard/WidgetListCoreObjects';

const buildListOutcome = async (containerId: string, widget: Widget) => {
  const [selection] = widget.dataSelection;
  const dataSelectionTypes = ['Stix-Core-Object'];
  const dateAttribute = selection.date_attribute && selection.date_attribute.length > 0
    ? selection.date_attribute
    : 'created_at';

  const { filters } = buildFiltersAndOptionsForTemplateWidgets(containerId, selection.filters);
  const variables = {
    types: dataSelectionTypes,
    first: selection.number ?? 10,
    orderBy: dateAttribute,
    orderMode: 'desc',
    filters,
  };

  const data = await fetchQuery<StixCoreObjectsListQuery>(stixCoreObjectsListQuery, variables).toPromise();
  console.log(data);
  return renderToString(
    <IntlProvider
      locale={'en'}
      key={'en'}
      messages={'Base message'}
      onError={(err) => {
        if (err.code === 'MISSING_TRANSLATION') {
          return;
        }
        throw err;
      }}
    >
      <WidgetListCoreObjects
        data={data.stixCoreObjects.edges}
        dateAttribute={dateAttribute}
        rootRef={undefined}
        widgetId={widget.id}
        pageSize={selection.number ?? 10}
      />
    </IntlProvider>,
  );
};

export default buildListOutcome;
