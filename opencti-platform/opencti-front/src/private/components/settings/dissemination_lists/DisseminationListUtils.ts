import * as Yup from 'yup';

export const disseminationListUpdateValidator = (t: (n: string) => string) => {
  return Yup.object().shape({
    name: Yup.string().trim().min(2).required(t('This field is required')),
    emails: Yup.string().required(t('This field is required')),
  });
};
export const disseminationListCreationValidator = (t: (value: string) => string) => {
  return Yup.object().shape({
    name: Yup.string().trim().min(2).required(t('This field is required')),
    emails: Yup.string().required(t('This field is required')),
  });
};
