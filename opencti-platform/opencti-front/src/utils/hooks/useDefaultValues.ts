import { head, isEmpty } from 'ramda';
import { FormikValues } from 'formik/dist/types';
import useEntitySettings from './useEntitySettings';
import useAuth from './useAuth';
import { Option } from '../../private/components/common/form/ReferenceField';
import useVocabularyCategory from './useVocabularyCategory';
import { isEmptyField } from '../utils';

export const useComputeDefaultValues = (entityType: string, attributeName: string, multiple: boolean, type: string, defaultValues: readonly { id: string, name: string }[]) => {
  const { fieldToCategory } = useVocabularyCategory();
  const ovCategory = fieldToCategory(entityType, attributeName);
  // Handle createdBy
  if (attributeName === 'createdBy') {
    return head(defaultValues.map((v) => ({ value: v.id, label: v.name } as Option))) ?? '';
  }
  // Handle OV
  if (ovCategory) {
    if (multiple) {
      return defaultValues.map((v) => (v.name));
    }
    return head(defaultValues.map((v) => (v.name))) ?? '';
  }
  if (multiple) {
    return defaultValues.map((v) => ({ value: v.id, label: v.name } as Option));
  }
  // Handle boolean
  if (type === 'boolean') {
    return Boolean(head(defaultValues)?.id);
  }

  // Handle single numeric & single string
  return head(defaultValues)?.id ?? '';
};

const useDefaultValues = <Values extends FormikValues>(id: string, initialValues: Values, notEmptyValues?: Partial<Values>) => {
  const entitySettings = useEntitySettings(id).at(0);
  if (!entitySettings) {
    throw Error(`Invalid type for setting: ${id}`);
  }
  const defaultValuesAttributes = [...entitySettings.defaultValuesAttributes];
  const keys = Object.keys(initialValues);
  const defaultValues: Record<string, unknown> = {};
  let enableDefaultMarking = false;
  defaultValuesAttributes.forEach((attr: { name: string, type: string, defaultValues: readonly { id: string, name: string }[] }) => {
    if (attr.name === 'objectMarking') {
      enableDefaultMarking = head(attr.defaultValues)?.id === 'true';
    } else if (keys.includes(attr.name) && isEmptyField(initialValues[attr.name])) {
      defaultValues[attr.name] = useComputeDefaultValues(entitySettings.target_type, attr.name, Array.isArray(initialValues[attr.name]), attr.type, attr.defaultValues);
    }
  });

  // Default confidence
  if (keys.includes('confidence') && isEmptyField(defaultValues.confidence)) {
    defaultValues.confidence = 75;
  }

  const { me } = useAuth();
  const defaultMarkings = me.default_marking;
  if (keys.includes('objectMarking') && isEmpty(initialValues.objectMarking) && enableDefaultMarking) {
    // Handle only GLOBAL entity type for now
    const defaultMarking = (defaultMarkings ?? []).filter((entry) => entry.entity_type === 'GLOBAL')[0]?.values ?? [];
    defaultValues.objectMarking = defaultMarking.map((o) => ({ label: o.definition, value: o.id }));
  }

  // Handle not empty values case
  if (notEmptyValues) {
    Object.keys(notEmptyValues).forEach((key) => {
      if (isEmptyField(defaultValues[key])) {
        defaultValues[key] = notEmptyValues[key];
      }
    });
  }

  return {
    ...initialValues,
    ...defaultValues,
  };
};

export default useDefaultValues;
