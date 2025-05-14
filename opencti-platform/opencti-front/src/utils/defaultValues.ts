import { Option } from '@components/common/form/ReferenceField';
import { AuthorizedMemberOption, INPUT_AUTHORIZED_MEMBERS } from './authorizedMembers';
import { AutoCompleteOption } from './field';

export type DefaultValues = AutoCompleteOption | AutoCompleteOption[] | Option | Option[] | string | (string | null)[] | boolean | null;

const isBoolean = (defaultValues: DefaultValues) => {
  return typeof defaultValues === 'boolean';
};

const isSingleOption = (defaultValues: DefaultValues) => {
  return (
    typeof defaultValues === 'object'
    && 'value' in (defaultValues as unknown as Option)
  );
};

const isMultipleOption = (defaultValues: DefaultValues) => {
  return Array.isArray(defaultValues) && defaultValues.some(isSingleOption);
};

/**
 * Transforms a default value in a format used in a form into
 * the format to stringify for backend.
 *
 * @param defaultValues The value in form format.
 * @param attributeName Optional name of the attribute of the default value.
 * @returns Default values as an array of string.
 */
export const defaultValuesToStringArray = (
  defaultValues: DefaultValues,
  attributeName?: string,
): string[] | null => {
  let default_values: string[] | null = null;
  if (defaultValues === null || defaultValues === '') return default_values;

  if (Array.isArray(defaultValues)) {
    if (attributeName === INPUT_AUTHORIZED_MEMBERS) {
      default_values = (defaultValues as AuthorizedMemberOption[])
        .filter((v) => v.accessRight !== 'none')
        .map((v) => JSON.stringify({
          id: v.value,
          access_right: v.accessRight,
          groups_restriction_ids: v.groupsRestriction ? v.groupsRestriction.map((g) => g.value) : [],
        }));
    } else if (isMultipleOption(defaultValues)) {
      // Handle multiple options
      default_values = defaultValues.map((v) => (v as Option).value);
    }
    // Handle single option
  } else if (isSingleOption(defaultValues)) {
    default_values = [(defaultValues as Option).value];
    // Handle single value
  } else if (isBoolean(defaultValues)) {
    default_values = [defaultValues.toString()];
  } else {
    // Default case -> string
    default_values = [defaultValues as string];
  }
  return default_values;
};
