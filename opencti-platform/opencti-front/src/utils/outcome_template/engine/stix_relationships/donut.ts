import { stixRelationshipsDonutsDistributionQuery } from '@components/common/stix_relationships/StixRelationshipsDonut';
import { buildFiltersAndOptionsForWidgets } from '../../../filters/filtersUtils';
import type { Widget } from '../../../widget/widget';
import { fetchQuery } from '../../../../relay/environment';

const buildDonutOutcome = async (containerId: string, widget: Widget) => {
  const [selection] = widget.dataSelection;

  const filtersAndOptions = buildFiltersAndOptionsForWidgets(selection.filters);
  const finalField = selection.attribute || 'entity_type';
  const variables = {
    field: finalField,
    operation: 'count',
    dateAttribute: selection.date_attribute ?? 'created_at',
    limit: selection.number ?? 10,
    filters: filtersAndOptions?.filters,
    isTo: selection.isTo,
    dynamicFrom: selection.dynamicFrom,
    dynamicTo: selection.dynamicTo,
  };

  const data = await fetchQuery(stixRelationshipsDonutsDistributionQuery, variables).toPromise();
  console.log(data);
  return 'pouet';
};

export default buildDonutOutcome;
