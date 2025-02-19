import * as Yup from 'yup';

export const statusValidation = (t: (name: string | object) => string) => Yup.object().shape({
  template: Yup.object().required(t('This field is required')),
  order: Yup.number()
    .typeError(t('The value must be a number'))
    .integer(t('The value must be a number'))
    .required(t('This field is required')),
});

export interface StatusForm {
  template: {
    label: string;
    value: string;
    color: string;
  } | null;
  order: string;
}
