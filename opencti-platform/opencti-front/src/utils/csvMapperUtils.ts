import { Option } from '@components/common/form/ReferenceField';

const resolveHasUserChoiceParsedCsvMapper = (option: Option & {
  representations: { attributes: { key: string; default_values: string[] }[] }[]
}) => {
  return option.representations.some(
    (representation) => representation.attributes.some(
      (attribute) => attribute.key === 'objectMarking' && attribute.default_values.includes('user-choice'),
    ),
  );
};

export default resolveHasUserChoiceParsedCsvMapper;
