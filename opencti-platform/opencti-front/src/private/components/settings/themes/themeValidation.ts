import * as Yup from 'yup';

const HEX_COLOR_REGEX = /^#[0-9a-fA-F]{6}$/;

const themeValidationSchema = (t_i18n: (key: string) => string) => {
  return Yup.object().shape({
    name: Yup.string()
      .trim()
      .min(2)
      .required(t_i18n('This field is required')),
    theme_background: Yup.string()
      .matches(HEX_COLOR_REGEX)
      .required(t_i18n('This field is required')),
    theme_paper: Yup.string()
      .matches(HEX_COLOR_REGEX)
      .required(t_i18n('This field is required')),
    theme_nav: Yup.string()
      .matches(HEX_COLOR_REGEX)
      .required(t_i18n('This field is required')),
    theme_primary: Yup.string()
      .matches(HEX_COLOR_REGEX)
      .required(t_i18n('This field is required')),
    theme_secondary: Yup.string()
      .matches(HEX_COLOR_REGEX)
      .required(t_i18n('This field is required')),
    theme_accent: Yup.string()
      .matches(HEX_COLOR_REGEX)
      .required(t_i18n('This field is required')),
    theme_text_color: Yup.string()
      .required(t_i18n('This field is required')),
    theme_logo: Yup.string().nullable(),
    theme_logo_collapsed: Yup.string().nullable(),
    theme_logo_login: Yup.string().nullable(),
  });
};

export default themeValidationSchema;
