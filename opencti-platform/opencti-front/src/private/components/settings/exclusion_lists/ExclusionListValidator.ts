import * as Yup from 'yup';

const exclusionListValidator = (t: (value: string) => string) => Yup.object().shape({
  name: Yup.string().trim().min(2).required(t('This field is required')),
  description: Yup.string().nullable(),
});

export default exclusionListValidator;
