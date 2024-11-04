import { fetchQuery } from '../../../../relay/environment';
import { StixCoreObjectsAttributesQuery$data } from './__generated__/StixCoreObjectsAttributesQuery.graphql';
import type { TemplateWidgetFromBackend } from '../../template';
import stixCoreObjectsAttributesQuery from './StixCoreObjectsAttributesQuery';
import getObjectProperty from '../../../object';
import { buildReadableAttribute } from '../../../String';

const useBuildAttributesOutcome = () => {
  const buildAttributesOutcome = async (
    containerId: string,
    templateWidget: TemplateWidgetFromBackend,
  ) => {
    const instanceId = templateWidget.widget.dataSelection[0].instance_id;
    if (!instanceId) {
      throw Error('The attribute widget should refers to an instance');
    }
    const queryVariables = { id: instanceId === 'SELF_ID' ? containerId : instanceId };
    const columns = templateWidget.widget.dataSelection[0].columns ?? [];
    const data = await fetchQuery(stixCoreObjectsAttributesQuery, queryVariables).toPromise() as StixCoreObjectsAttributesQuery$data;

    return columns.map((col) => {
      let result;
      try {
        result = getObjectProperty(data.stixCoreObject ?? {}, col.attribute) ?? '';
      } catch (e) {
        result = '';
      }
      const attributeData = buildReadableAttribute(result, col);
      return {
        variableName: col.variableName,
        attributeData,
      };
    });
  };
  return { buildAttributesOutcome };
};

export default useBuildAttributesOutcome;
