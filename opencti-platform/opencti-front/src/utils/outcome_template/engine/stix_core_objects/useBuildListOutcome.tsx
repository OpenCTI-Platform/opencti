import { stixCoreObjectsListQuery } from '@components/common/stix_core_objects/StixCoreObjectsList';
import { StixCoreObjectsListQuery$data } from '@components/common/stix_core_objects/__generated__/StixCoreObjectsListQuery.graphql';
import React from 'react';
import { renderToString } from 'react-dom/server';
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
    const columns = selection.columns ?? [
      { label: 'Entity type', attribute: 'entity_type' },
      { label: 'Representative', attribute: 'representative.main' },
      { label: 'Creation date', attribute: 'created_at' },
    ];

    return renderToString(
      <table>
        <thead>
          <tr>
            {columns.map((col) => (
              <th key={col.attribute}>{col.label}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {nodes.map((n) => (
            <tr key={n.id}>
              {columns.map((col) => {
                const splittedAttribute = col.attribute.split('.');
                const displayedAttribute = splittedAttribute.length === 1
                  ? n[col.attribute]
                  : n[splittedAttribute[0]][splittedAttribute[1]];
                return (
                  <td key={`${n.id}-${col.attribute}`}>{displayedAttribute}</td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>,
    );
  };
  return { buildListOutcome };
};

export default useBuildListOutcome;
