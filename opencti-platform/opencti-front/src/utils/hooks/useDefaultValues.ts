import { head, isEmpty } from 'ramda';
import { FormikValues } from 'formik/dist/types';
import { EntitySettingAttributeEditionMembersQuery$data } from '@components/settings/sub_types/entity_setting/__generated__/EntitySettingAttributeEditionMembersQuery.graphql';
import { Option } from '@components/common/form/ReferenceField';
import { useCallback } from 'react';
import useEntitySettings from './useEntitySettings';
import useAuth from './useAuth';
import useVocabularyCategory from './useVocabularyCategory';
import { isEmptyField } from '../utils';
import { now } from '../Time';
import { AuthorizedMembers, authorizedMembersToOptions, INPUT_AUTHORIZED_MEMBERS } from '../authorizedMembers';
import useConfidenceLevel from './useConfidenceLevel';

const DEFAULT_CONFIDENCE = 75;

export const useComputeDefaultValues = () => {
  const { fieldToCategory } = useVocabularyCategory();

  return useCallback((
    entityType: string,
    attributeName: string,
    multiple: boolean,
    type: string,
    defaultValues: readonly { id: string; name: string }[],
    membersData?: EntitySettingAttributeEditionMembersQuery$data,
  ) => {
    const ovCategory = fieldToCategory(entityType, attributeName);
    // Handle createdBy
    if (attributeName === 'createdBy') {
      return (
        head(
          defaultValues.map((v) => ({ value: v.id, label: v.name })),
        ) ?? ''
      );
    }

    // Handle object marking specific case : activate or deactivate default values (handle in access)
    if (attributeName === 'objectMarking') {
      return defaultValues[0]?.id ?? false;
    }

    if (attributeName === INPUT_AUTHORIZED_MEMBERS) {
      const defaultAuthorizedMembers: AuthorizedMembers = defaultValues
        .map((v) => {
          const parsed = JSON.parse(v.id);
          const member = membersData?.members?.edges?.find(({ node }) => node.id === parsed.id);
          return {
            id: parsed.id,
            name: member?.node.name ?? '',
            entity_type: member?.node.entity_type ?? '',
            access_right: parsed.access_right,
          };
        })
        .filter((v) => !!v.id && !!v.access_right);

      return defaultAuthorizedMembers.length > 0
        ? authorizedMembersToOptions(defaultAuthorizedMembers)
        : null;
    }

    // Handle OV
    if (ovCategory) {
      if (multiple) {
        return defaultValues.map((v) => v.name);
      }
      return head(defaultValues.map((v) => v.name)) ?? '';
    }
    if (multiple) {
      return defaultValues.map((v) => ({ value: v.id, label: v.name } as Option));
    }
    // Handle boolean
    if (type === 'boolean') {
      if ((defaultValues)[0]?.id === 'true') {
        return true;
      }
      if ((defaultValues)[0]?.id === 'false') {
        return false;
      }
      return null;
    }

    // Handle single numeric & single string
    return head(defaultValues)?.id ?? '';
  }, [fieldToCategory]);
};

const useDefaultValues = <Values extends FormikValues>(
  id: string,
  initialValues: Values,
  notEmptyValues?: Partial<Values>,
) => {
  const computeDefaultValues = useComputeDefaultValues();
  const { getEffectiveConfidenceLevel } = useConfidenceLevel();

  const entitySettings = useEntitySettings(id).at(0);
  if (!entitySettings) {
    throw Error(`Invalid type for setting: ${id}`);
  }
  const defaultValuesAttributes = [...entitySettings.defaultValuesAttributes];
  const keys = Object.keys(initialValues);
  const defaultValues: Record<string, unknown> = {};
  let enableDefaultMarking = false;
  defaultValuesAttributes.forEach(
    (attr: {
      name: string;
      type: string;
      defaultValues: readonly { id: string; name: string }[];
    }) => {
      if (attr.name === 'objectMarking') {
        enableDefaultMarking = head(attr.defaultValues)?.id === 'true';
      } else if (
        keys.includes(attr.name)
        && isEmptyField(initialValues[attr.name])
      ) {
        defaultValues[attr.name] = computeDefaultValues(
          entitySettings.target_type,
          attr.name,
          Array.isArray(initialValues[attr.name]),
          attr.type,
          attr.defaultValues,
        );
      }
    },
  );

  // Default confidence is computed from the user's effective level
  if (keys.includes('confidence') && isEmptyField(initialValues.confidence) && isEmptyField(defaultValues.confidence)) {
    const level = getEffectiveConfidenceLevel(id);
    defaultValues.confidence = level ?? DEFAULT_CONFIDENCE;
  }

  // Default published
  if (keys.includes('published') && isEmptyField(initialValues.published) && isEmptyField(defaultValues.published)) {
    defaultValues.published = now();
  }

  // Default published
  if (keys.includes('created') && isEmptyField(initialValues.created) && isEmptyField(defaultValues.created)) {
    defaultValues.created = now();
  }

  const { me } = useAuth();
  const defaultMarkings = me.default_marking;
  if (
    keys.includes('objectMarking')
    && isEmpty(initialValues.objectMarking)
    && enableDefaultMarking
  ) {
    // Handle only GLOBAL entity type for now
    const defaultMarking = (defaultMarkings ?? []).filter(
      (entry) => entry.entity_type === 'GLOBAL',
    )[0]?.values ?? [];
    defaultValues.objectMarking = defaultMarking.map((o) => ({
      label: o.definition,
      value: o.id,
    }));
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
