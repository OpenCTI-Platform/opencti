import * as Yup from 'yup';

const HEX_COLOR_REGEX = /^#[0-9a-fA-F]{6}$/;

const themeValidationSchema = (t_i18n: (key: string) => string) => {
  const requiredMsg = t_i18n('This field is required');
  const invalidColorMsg = t_i18n('Invalid color format');

  return Yup.object({
    name: Yup.string()
      .trim()
      .min(2)
      .required(requiredMsg),

    theme_background: Yup.string()
      .matches(HEX_COLOR_REGEX, invalidColorMsg)
      .required(requiredMsg),

    theme_paper: Yup.string()
      .matches(HEX_COLOR_REGEX, invalidColorMsg)
      .required(requiredMsg),

    theme_nav: Yup.string()
      .matches(HEX_COLOR_REGEX, invalidColorMsg)
      .required(requiredMsg),

    theme_primary: Yup.string()
      .matches(HEX_COLOR_REGEX, invalidColorMsg)
      .required(requiredMsg),

    theme_secondary: Yup.string()
      .matches(HEX_COLOR_REGEX, invalidColorMsg)
      .required(requiredMsg),

    theme_accent: Yup.string()
      .matches(HEX_COLOR_REGEX, invalidColorMsg)
      .required(requiredMsg),

    theme_text_color: Yup.string()
      .matches(HEX_COLOR_REGEX, invalidColorMsg)
      .required(requiredMsg),

    theme_logo: Yup.string().nullable(),
    theme_logo_collapsed: Yup.string().nullable(),
    theme_logo_login: Yup.string().nullable(),

    // the theme login aside validation is based on the type of aside selected,
    // because depeding on the type, the required fields are different
    theme_login_aside_type: Yup.mixed<
      '' | 'color' | 'gradient' | 'image'
    >().oneOf(['', 'color', 'gradient', 'image']),

    /**
     * COLOR
     */
    theme_login_aside_color: Yup.string()
      .nullable()
      .when('theme_login_aside_type', {
        is: 'color',
        then: (schema) =>
          schema
            .matches(HEX_COLOR_REGEX, invalidColorMsg)
            .required(requiredMsg),
        otherwise: (schema) => schema.strip(),
      }),

    /**
     * GRADIENT START & END
     */
    theme_login_aside_gradient_start: Yup.string()
      .nullable()
      .when('theme_login_aside_type', {
        is: 'gradient',
        then: (schema) =>
          schema
            .matches(HEX_COLOR_REGEX, invalidColorMsg)
            .required(requiredMsg),
        otherwise: (schema) => schema.strip(),
      }),
    theme_login_aside_gradient_end: Yup.string()
      .nullable()
      .when('theme_login_aside_type', {
        is: 'gradient',
        then: (schema) =>
          schema
            .matches(HEX_COLOR_REGEX, invalidColorMsg)
            .required(requiredMsg),
        otherwise: (schema) => schema.strip(),
      }),

    /**
     * IMAGE
     */
    theme_login_aside_image: Yup.string()
      .nullable()
      .when('theme_login_aside_type', {
        is: 'image',
        then: (schema) => schema.required(requiredMsg),
        otherwise: (schema) => schema.strip(),
      }),
  });
};

export default themeValidationSchema;
