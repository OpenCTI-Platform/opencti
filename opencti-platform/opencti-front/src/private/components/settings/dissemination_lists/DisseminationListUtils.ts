import * as Yup from 'yup';

export const disseminationListValidator = (t: (value: string) => string) => {
  return Yup.object().shape({
    name: Yup.string().trim().min(2).required(t('This field is required')),
    description: Yup.string(),
    emails: Yup.string()
      .required(t('This field is required'))
      .test(
        'emails',
        t('Each line must contain a valid email address'),
        (value) => {
          const emails = value.split('\n').map((email) => email.trim());
          return emails.every((email) => email !== '' && Yup.string().email().isValidSync(email));
        },
      )
      .test(
        'max-emails',
        t('You cannot add more than 500 e-mail addresses'),
        (value) => {
          const emails = value.split('\n').map((email) => email.trim());
          return emails.length <= 500;
        },
      ),
  });
};

export const formatEmailsForApi = (value: string) => {
  return value.replaceAll('\n', ',').replaceAll(/\s/g, '');
};

export const formatEmailsForFront = (value: string) => {
  return value.replaceAll(',', '\n');
};
