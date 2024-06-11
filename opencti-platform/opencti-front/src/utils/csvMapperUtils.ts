import { CsvMapperFieldOption } from '@components/common/form/CsvMapperField';

const resolveHasUserChoiceParsedCsvMapper = (option: CsvMapperFieldOption) => {
  return option.representations.some(
    (representation) => representation.attributes.some(
      (attribute) => attribute.key === 'objectMarking' && attribute.default_values.some(({ name }) => name === 'user-choice'),
    ),
  );
};

export default resolveHasUserChoiceParsedCsvMapper;
