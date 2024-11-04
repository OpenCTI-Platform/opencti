import { stixCoreObjectsListQuery } from '@components/common/stix_core_objects/StixCoreObjectsList';
import { StixCoreObjectsListQuery$data } from '@components/common/stix_core_objects/__generated__/StixCoreObjectsListQuery.graphql';
import React from 'react';
import { renderToString } from 'react-dom/server';
import { useBuildFiltersForTemplateWidgets } from '../../../filters/filtersUtils';
import { fetchQuery } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import getObjectProperty from '../../../object';
import type { WidgetFromBackend } from '../../../widget/widget';
import { buildReadableAttribute } from '../../../String';

const useBuildListOutcome = () => {
  const { t_i18n } = useFormatter();
  const { buildFiltersForTemplateWidgets } = useBuildFiltersForTemplateWidgets();

  const buildListOutcome = async (
    containerId: string,
    widget: WidgetFromBackend,
    maxContentMarkings: string[],
  ) => {
    const [selection] = widget.dataSelection;
    const dataSelectionTypes = ['Stix-Core-Object'];
    const dateAttribute = selection.date_attribute && selection.date_attribute.length > 0
      ? selection.date_attribute
      : 'created_at';

    const filters = buildFiltersForTemplateWidgets(containerId, selection.filters, maxContentMarkings);

    const variables = {
      types: dataSelectionTypes,
      first: selection.number ?? 1000,
      orderBy: dateAttribute,
      orderMode: 'desc',
      filters,
    };

    const data = await fetchQuery(stixCoreObjectsListQuery, variables).toPromise() as StixCoreObjectsListQuery$data;
    const nodes = (data.stixCoreObjects?.edges ?? []).map((n) => n.node) ?? [];
    const columns = selection.columns ?? [
      { label: t_i18n('Entity type'), attribute: 'entity_type' },
      { label: t_i18n('Representative'), attribute: 'representative.main' },
      { label: t_i18n('Creation date'), attribute: 'created_at' },
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
                let property;
                try {
                  property = getObjectProperty(n, col.attribute) ?? '';
                } catch (e) {
                  property = '';
                }
                const strAttribute = buildReadableAttribute(property, col);
                // The trick here is to add a zero-width space every 10 chars to be able to make a
                // multiline text even for values like long IDs without spaces.
                const wrappableAttribute = (strAttribute.match(/.{1,10}/g) ?? []).join('\u{200B}');
                return <td key={`${n.id}-${col.attribute}`}>{wrappableAttribute}</td>;
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
