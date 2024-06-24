import { CsvMapperFieldOption } from '@components/common/form/CsvMapperField';

export const USER_CHOICE_MARKING_CONFIG = 'user-choice';
export const resolveHasUserChoiceParsedCsvMapper = (option: CsvMapperFieldOption) => {
  return option.representations.some(
    (representation) => representation.attributes.some(
      (attribute) => attribute.key === 'objectMarking' && attribute.default_values.some((value) => {
        if (typeof value === 'string') {
          return value === USER_CHOICE_MARKING_CONFIG;
        }
        return value?.name === USER_CHOICE_MARKING_CONFIG;
      }),
    ),
  );
};
