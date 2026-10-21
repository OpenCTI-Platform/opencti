import { renderToString } from 'react-dom/server';
import { fetchQuery } from '../../../../relay/environment';
import { StixCoreObjectsAttributesQuery$data } from './__generated__/StixCoreObjectsAttributesQuery.graphql';
import stixCoreObjectsAttributesQuery from './StixCoreObjectsAttributesQuery';
import type { Widget } from '../../../widget/widget';
import useBuildReadableAttribute from '../../../hooks/useBuildReadableAttribute';
import { getObjectPropertyWithoutEmptyValues } from '../../../object';
import { SELF_ID } from '../../../filters/filtersUtils';
import { getCustomFieldRawValueByFieldName, isCustomFieldAttribute } from '../../../customFields';
import { useFormatter } from '../../../../components/i18n';
import { isSemanticallyEmptyHtmlFragment } from '../templateSectionUtils';

export type AttributeOutcome = {
  variableName: string | null | undefined;
  attributeData: string;
  isEmpty: boolean;
  preserveSection?: boolean;
  error?: unknown;
};

type BuildAttributesOutcomeOptions = {
  includeMetadata?: boolean;
};

const isRawAttributeEmpty = (value: unknown): boolean => {
  if (value === null || value === undefined) {
    return true;
  }

  if (typeof value === 'string') {
    return isSemanticallyEmptyHtmlFragment(value);
  }

  if (Array.isArray(value)) {
    return value.length === 0 || value.every((item) => isRawAttributeEmpty(item));
  }

  if (typeof value === 'object') {
    const values = Object.values(value as Record<string, unknown>);
    return values.length === 0 || values.every((item) => isRawAttributeEmpty(item));
  }

  return false;
};

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
    options?: BuildAttributesOutcomeOptions,
    notAllowedMarkingIds: string[] = [],
  ): Promise<AttributeOutcome[]> => {
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

    return (columns ?? []).flatMap((col) => {
      if (isReadThroughNotAllowedObject(data.stixCoreObject ?? {}, col.attribute ?? '', notAllowedMarkingIds)) {
        return [{
          variableName: col.variableName,
          attributeData: t_i18n('Withheld: marked above the marking limits of this export'),
          isEmpty: false,
        }];
      }
      try {
        const result = isCustomFieldAttribute(col.attribute)
          ? getCustomFieldRawValueByFieldName(data.stixCoreObject?.customFieldValues, col.attribute ?? '') ?? ''
          // With metadata, a missing intermediate value (e.g. createdBy.name without author) is an empty value, not an error.
          : getObjectPropertyWithoutEmptyValues(data.stixCoreObject ?? {}, col.attribute ?? '', options?.includeMetadata ? { nullableSubparts: true } : undefined);
        const isEmpty = options?.includeMetadata ? isRawAttributeEmpty(result) : false;
        const readableAttribute = options?.includeMetadata && isEmpty
          ? ''
          : buildReadableAttribute(result, col);
        const attributeData = typeof readableAttribute === 'string'
          ? readableAttribute
          : renderToString(readableAttribute);

        return [{
          variableName: col.variableName,
          attributeData,
          isEmpty,
        }];
      } catch (error) {
        if (!options?.includeMetadata) {
          return [{
            variableName: col.variableName,
            attributeData: '',
            isEmpty: false,
          }];
        }

        if (!col.variableName) {
          return [];
        }

        return [{
          variableName: col.variableName,
          attributeData: `$${col.variableName}`,
          isEmpty: false,
          preserveSection: true,
          error,
        }];
      }
    });
  };

  return { buildAttributesOutcome };
};

export default useBuildAttributesOutcome;
