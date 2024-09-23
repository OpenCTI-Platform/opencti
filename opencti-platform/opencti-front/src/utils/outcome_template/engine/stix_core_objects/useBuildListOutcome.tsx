import { stixCoreObjectsListQuery } from '@components/common/stix_core_objects/StixCoreObjectsList';
import { StixCoreObjectsListQuery$data } from '@components/common/stix_core_objects/__generated__/StixCoreObjectsListQuery.graphql';
import { useBuildFiltersForTemplateWidgets } from '../../../filters/filtersUtils';
import type { Widget } from '../../../widget/widget';
import { fetchQuery } from '../../../../relay/environment';

const useBuildListOutcome = () => {
  const { buildFiltersForTemplateWidgets } = useBuildFiltersForTemplateWidgets();

  const buildListOutcome = async (containerId: string, widget: Widget, maxContentMarkings: string[]) => {
    const [selection] = widget.dataSelection;
    const dataSelectionTypes = ['Stix-Core-Object'];
    const dateAttribute = selection.date_attribute && selection.date_attribute.length > 0
      ? selection.date_attribute
      : 'created_at';

    const filters = buildFiltersForTemplateWidgets(containerId, selection.filters, maxContentMarkings);

    const variables = {
      types: dataSelectionTypes,
      first: selection.number ?? 10,
      orderBy: dateAttribute,
      orderMode: 'desc',
      filters,
    };

    const data = await fetchQuery(stixCoreObjectsListQuery, variables).toPromise() as StixCoreObjectsListQuery$data;
    const nodes = (data.stixCoreObjects?.edges ?? []).map((n) => n.node) ?? [];
    const rows = nodes.map((n) => `
    <tr>
      <td>${n.entity_type}</td>
      <td>${n.representative.main}</td>
      <td>${n.created_at}</td>
    </tr>
  `).join('\n');
    return (
      `<table>
      <tr>
        <th>Entity type</th>
        <th>Representative</th>
        <th>Creation date</th>
      </tr>
      ${rows}
    </table>`
    );
  };
  return { buildListOutcome };
};

export default useBuildListOutcome;
