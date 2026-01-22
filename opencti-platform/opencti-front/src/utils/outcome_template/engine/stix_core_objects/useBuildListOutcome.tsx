import { stixCoreObjectsListQuery } from '@components/common/stix_core_objects/StixCoreObjectsList';
import { StixCoreObjectsListQuery$data } from '@components/common/stix_core_objects/__generated__/StixCoreObjectsListQuery.graphql';
import React from 'react';
import { renderToString } from 'react-dom/server';
import { stixRelationshipsListQuery } from '@components/common/stix_relationships/StixRelationshipsList';
import { StixRelationshipsListQuery$data } from '@components/common/stix_relationships/__generated__/StixRelationshipsListQuery.graphql';
import { fetchQuery } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import type { Widget, WidgetPerspective } from '../../../widget/widget';
import useBuildReadableAttribute from '../../../hooks/useBuildReadableAttribute';
import { getObjectPropertyWithoutEmptyValues } from '../../../object';
import { RELATIONSHIP_WIDGETS_TYPES } from '../../../widget/widgetUtils';

type ListItem = object & { id: string };

const useBuildListOutcome = () => {
  const { t_i18n } = useFormatter();
  const { buildReadableAttribute } = useBuildReadableAttribute();

  const buildListOutcome = async (
    dataSelection: Pick<Widget['dataSelection'][0], 'filters' | 'number' | 'columns' | 'sort_mode' | 'sort_by'>,
    widgetPerspective?: WidgetPerspective | null,
  ) => {
    const variables = {
      first: dataSelection.number ?? 10,
      orderBy: dataSelection.sort_by ?? 'created_at',
      orderMode: dataSelection.sort_mode ?? 'asc',
      filters: dataSelection.filters,
    };

    let nodes: ListItem[] = [];
    if (widgetPerspective === 'entities') {
      const types = ['Stix-Core-Object'];
      const data = await fetchQuery(stixCoreObjectsListQuery, { ...variables, types }).toPromise() as StixCoreObjectsListQuery$data;
      nodes = (data.stixCoreObjects?.edges ?? []).map((n) => n.node) ?? [];
    } else if (widgetPerspective === 'relationships') {
      const types = RELATIONSHIP_WIDGETS_TYPES;
      const data = await fetchQuery(stixRelationshipsListQuery, { ...variables, types }).toPromise() as StixRelationshipsListQuery$data;
      nodes = (data.stixRelationships?.edges ?? []).flatMap((n) => (n ? n.node : [])) ?? [];
    } else {
      throw Error(t_i18n('Perspective of fintel template list widget should be either "entities" or "relationships"'));
    }
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
                } catch (_e) {
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
