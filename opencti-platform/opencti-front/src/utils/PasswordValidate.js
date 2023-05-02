import * as Yup from 'yup';
import PasswordValidator from 'password-validator';
import { fetchQuery } from '../relay/environment';

const fetchDefaultSettings = graphql`
  query PasswordValidateSettingsQuery {
    settings {
      password_config_min_length
      password_config_max_length
      password_config_uppercase
      password_config_lowercase
      password_config_digits
      password_config_special_char
    }
  }
`;

export const passwordValidate = (errorMessage) => Yup.string()
  .test('test-password', errorMessage, async function (value) {
    let d;
    await fetchQuery(fetchDefaultSettings, {}).toPromise().then(data => d = {
      min_length: data?.settings?.password_config_min_length ?? 10,
      max_length: data?.settings?.password_config_max_length ?? 50,
      digits: data?.settings?.password_config_digits ?? 1,
      uppercase: data?.settings?.password_config_uppercase ?? 1,
      symbols:data?.settings?.password_config_special_char ?? 1,
    });
    const { path, createError } = this;
    const schema = new PasswordValidator();
    schema.is().min(d.min_length, `minimum of ${d.min_length} characters`);
    schema.is().max(d.max_length, `maximum of ${d.max_length} characters`);
    schema.has().digits(d.digits, `minimum of ${d.digits} number`);
    schema.has().uppercase(d.uppercase,`minimum of ${d.uppercase} capitalized letter`);
    schema.has().symbols(d.symbols, `minimum of ${d.symbols} special character`);
    // ####################################################################################
    // TODO: Should read in a static JSON list of known bad passwords
    // schema.is().not().oneOf(['opencti','p@ssw0rd','Password','password','P@ssword','P@ssword1'], 'password not allowed');
    // ####################################################################################
    // TODO: Improvement - check for repeating pattern like qwertyqwerty
    // const pattern = /^([a-z])\2+$/;
    // schema.is().not([pattern], 'pattern is not allowed');
    // ####################################################################################
    const errors = schema.validate(value, { details: true }).map(({ message }) => message);
    let message = `${errorMessage}:`;
    for (const error of errors) {
      message += `\n - ${error}`
    }
      return (
        (value && schema.validate(value))||
        createError({ path, message })
      );
  });
