import * as Yup from 'yup';
import { useFormatter } from '../../../../components/i18n';

const { t_i18n } = useFormatter();

export const disseminationListValidator = () => {
  return Yup.object().shape({
    name: Yup.string().trim().min(2).required(t_i18n('This field is required')),
    description: Yup.string(),
    emails: Yup.string()
      .required(t_i18n('This field is required'))
      .test(
        'emails',
        t_i18n('Each line must contain a valid email address'),
        (value) => {
          const emails = value.split('\n').map((email) => email.trim());
          return emails.every((email) => email !== '' && Yup.string().email().isValidSync(email));
        },
      )
      .test(
        'max-emails',
        t_i18n('You cannot have more than 500 e-mail addresses'),
        (value) => {
          const emails = value.split('\n').map((email) => email.trim());
          return emails.length <= 500;
        },
      ),
  });
};

// remove white space and split on linebreaks to build an array
export const formatEmailsForApi = (value: string) => {
  return value.split('\n').map((elem) => elem.trim());
};

// build a string with linebreaks from an array
export const formatEmailsForFront = (value: string[] | readonly string[]) => {
  return value.join('\n');
};
