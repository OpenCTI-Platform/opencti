import { renderToString } from 'react-dom/server';
import { fetchQuery } from '../../../../relay/environment';
import { StixCoreObjectsAttributesQuery$data } from './__generated__/StixCoreObjectsAttributesQuery.graphql';
import stixCoreObjectsAttributesQuery from './StixCoreObjectsAttributesQuery';
import type { Widget } from '../../../widget/widget';
import useBuildReadableAttribute from '../../../hooks/useBuildReadableAttribute';
import { getObjectPropertyWithoutEmptyValues } from '../../../object';
import { SELF_ID } from '../../../filters/filtersUtils';
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

const useBuildAttributesOutcome = () => {
  const { buildReadableAttribute } = useBuildReadableAttribute();

  const buildAttributesOutcome = async (
    containerId: string,
    dataSelection: Pick<Widget['dataSelection'][0], 'instance_id' | 'columns'>,
    options?: BuildAttributesOutcomeOptions,
  ): Promise<AttributeOutcome[]> => {
    const { instance_id, columns } = dataSelection;
    if (!instance_id) {
      throw Error('The attribute widget should refers to an instance');
    }
    const queryVariables = { id: instance_id === SELF_ID ? containerId : instance_id };
    const data = await fetchQuery(
      stixCoreObjectsAttributesQuery,
      queryVariables,
    ).toPromise() as StixCoreObjectsAttributesQuery$data;

    return (columns ?? []).flatMap((col) => {
      try {
        const result = getObjectPropertyWithoutEmptyValues(data.stixCoreObject ?? {}, col.attribute ?? '');
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
