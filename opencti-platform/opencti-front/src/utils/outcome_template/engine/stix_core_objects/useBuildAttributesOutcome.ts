import { renderToString } from 'react-dom/server';
import { fetchQuery } from '../../../../relay/environment';
import { StixCoreObjectsAttributesQuery$data } from './__generated__/StixCoreObjectsAttributesQuery.graphql';
import stixCoreObjectsAttributesQuery from './StixCoreObjectsAttributesQuery';
import type { Widget } from '../../../widget/widget';
import useBuildReadableAttribute from '../../../hooks/useBuildReadableAttribute';
import { getObjectPropertyWithoutEmptyValues } from '../../../object';
import { SELF_ID } from '../../../filters/filtersUtils';
import { useFormatter } from '../../../../components/i18n';

// A nested object read by a column (the latest investigation run of a case)
// can be marked above the instance itself: its values follow its markings,
// whether the column selects one of its fields or the whole object.
export const isReadThroughNotAllowedObject = (
  instance: object,
  attribute: string,
  notAllowedMarkingIds: string[],
) => {
  if (notAllowedMarkingIds.length === 0) return false;
  let current: unknown = instance;
  for (const segment of attribute.split('.')) {
    if (!current || typeof current !== 'object' || Array.isArray(current)) return false;
    current = (current as Record<string, unknown>)[segment];
    const markings = (current as { objectMarking?: readonly ({ id?: string } | null)[] | null } | null | undefined)?.objectMarking;
    if (Array.isArray(markings) && markings.some((marking) => !!marking?.id && notAllowedMarkingIds.includes(marking.id))) {
      return true;
    }
  }
  return false;
};

const LATEST_INVESTIGATION_RUN = 'latestInvestigationRun';

// The latest investigation run costs a run lookup and the live checks of its
// sources: only fetch it when a column of the widget reads it.
export const selectsLatestInvestigationRun = (
  columns: Pick<Widget['dataSelection'][0], 'columns'>['columns'],
) => (columns ?? []).some(({ attribute }) => attribute === LATEST_INVESTIGATION_RUN
  || !!attribute?.startsWith(`${LATEST_INVESTIGATION_RUN}.`));

const useBuildAttributesOutcome = () => {
  const { t_i18n } = useFormatter();
  const { buildReadableAttribute } = useBuildReadableAttribute();

  const buildAttributesOutcome = async (
    containerId: string,
    dataSelection: Pick<Widget['dataSelection'][0], 'instance_id' | 'columns'>,
    notAllowedMarkingIds: string[] = [],
  ) => {
    const { instance_id, columns } = dataSelection;
    if (!instance_id) {
      throw Error('The attribute widget should refers to an instance');
    }
    const queryVariables = {
      id: instance_id === SELF_ID ? containerId : instance_id,
      withInvestigationRun: selectsLatestInvestigationRun(columns),
    };
    const data = await fetchQuery(
      stixCoreObjectsAttributesQuery,
      queryVariables,
    ).toPromise() as StixCoreObjectsAttributesQuery$data;

    return (columns ?? []).map((col) => {
      if (isReadThroughNotAllowedObject(data.stixCoreObject ?? {}, col.attribute ?? '', notAllowedMarkingIds)) {
        return {
          variableName: col.variableName,
          attributeData: t_i18n('Withheld: marked above the marking limits of this export'),
        };
      }
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
