import * as Yup from 'yup';

const exclusionListValidator = (t: (value: string) => string, isCreatedWithFile: boolean) => {
  return Yup.object().shape({
    name: Yup.string().trim().min(2).required(t('This field is required')),
    description: Yup.string().nullable(),
    exclusion_list_entity_types: Yup.array().min(1, t('Minimum one entity type')).required(t('This field is required')),
    file: isCreatedWithFile ? Yup.mixed().required(t('This field is required')) : Yup.mixed().nullable(),
    content: isCreatedWithFile ? Yup.string().nullable() : Yup.string().required(t('This field is required')),
  });
};

export default exclusionListValidator;
