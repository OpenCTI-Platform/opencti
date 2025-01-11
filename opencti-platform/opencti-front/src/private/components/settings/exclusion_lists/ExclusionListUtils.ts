import * as Yup from 'yup';

export const availableEntityTypes = ['Artifact', 'Domain-Name', 'Hostname', 'Url', 'StixFile', 'Email-Addr', 'IPv4-Addr', 'IPv6-Addr'];

export const exclusionListValidator = (t: (value: string) => string, isCreatedWithFile: boolean) => {
  return Yup.object().shape({
    name: Yup.string().trim().min(2).required(t('This field is required')),
    description: Yup.string().nullable(),
    exclusion_list_entity_types: Yup.array().min(1, t('Minimum one entity type')).required(t('This field is required')),
    file: isCreatedWithFile ? Yup.mixed().required(t('This field is required')) : Yup.mixed().nullable(),
    content: isCreatedWithFile ? Yup.string().nullable() : Yup.string().required(t('This field is required')),
  });
};
