import { stixCoreObjectsListQuery } from '@components/common/stix_core_objects/StixCoreObjectsList';
import { StixCoreObjectsListQuery$data } from '@components/common/stix_core_objects/__generated__/StixCoreObjectsListQuery.graphql';
import React from 'react';
import { renderToString } from 'react-dom/server';
import { fetchQuery } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import type { Widget } from '../../../widget/widget';
import useBuildReadableAttribute from '../../../hooks/useBuildReadableAttribute';
import { getObjectPropertyWithoutEmptyValues } from '../../../object';

const useBuildListOutcome = () => {
  const { t_i18n } = useFormatter();
  const { buildReadableAttribute } = useBuildReadableAttribute();

  const buildListOutcome = async (
    dataSelection: Pick<Widget['dataSelection'][0], 'date_attribute' | 'filters' | 'number' | 'columns'>,
  ) => {
    const dateAttribute = dataSelection.date_attribute || 'created_at';
    const variables = {
      types: ['Stix-Core-Object'],
      first: dataSelection.number ?? 1000,
      orderBy: dateAttribute,
      orderMode: 'desc',
      filters: dataSelection.filters,
    };

    const data = await fetchQuery(stixCoreObjectsListQuery, variables).toPromise() as StixCoreObjectsListQuery$data;
    const nodes = (data.stixCoreObjects?.edges ?? []).map((n) => n.node) ?? [];
    const columns = dataSelection.columns ?? [
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
                  property = getObjectPropertyWithoutEmptyValues(n, col.attribute ?? '');
                } catch (e) {
                  property = '';
                }
                const readableAttribute = buildReadableAttribute(property, col, true);
                return <td key={`${n.id}-${col.attribute}`}>{readableAttribute}</td>;
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
