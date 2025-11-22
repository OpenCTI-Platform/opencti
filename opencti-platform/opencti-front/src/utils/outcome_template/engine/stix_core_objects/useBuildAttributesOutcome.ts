import { renderToString } from 'react-dom/server';
import { fetchQuery } from '../../../../relay/environment';
import { StixCoreObjectsAttributesQuery$data } from './__generated__/StixCoreObjectsAttributesQuery.graphql';
import stixCoreObjectsAttributesQuery from './StixCoreObjectsAttributesQuery';
import type { Widget } from '../../../widget/widget';
import useBuildReadableAttribute from '../../../hooks/useBuildReadableAttribute';
import { getObjectPropertyWithoutEmptyValues } from '../../../object';
import { SELF_ID } from '../../../filters/filtersUtils';

const useBuildAttributesOutcome = () => {
  const { buildReadableAttribute } = useBuildReadableAttribute();

  const buildAttributesOutcome = async (
    containerId: string,
    dataSelection: Pick<Widget['dataSelection'][0], 'instance_id' | 'columns'>,
  ) => {
    const { instance_id, columns } = dataSelection;
    if (!instance_id) {
      throw Error('The attribute widget should refers to an instance');
    }
    const queryVariables = { id: instance_id === SELF_ID ? containerId : instance_id };
    const data = await fetchQuery(
      stixCoreObjectsAttributesQuery,
      queryVariables,
    ).toPromise() as StixCoreObjectsAttributesQuery$data;

    return (columns ?? []).map((col) => {
      let result;
      try {
        result = getObjectPropertyWithoutEmptyValues(data.stixCoreObject ?? {}, col.attribute ?? '');
      } catch (_e) {
        result = '';
      }
      const readableAttribute = buildReadableAttribute(result, col);
      return {
        variableName: col.variableName,
        attributeData: typeof readableAttribute === 'string'
          ? readableAttribute
          : renderToString(readableAttribute),
      };
    });
  };

  return { buildAttributesOutcome };
};

export default useBuildAttributesOutcome;
