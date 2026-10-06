import * as Yup from 'yup';

interface DeploySetting {
  readonly key: string;
  readonly type: string;
  readonly secret: boolean;
}

type Translate = (message: string) => string;

export const deploySettingsValidation = (settings: readonly DeploySetting[], t_i18n: Translate) => Yup.object().shape(Object.fromEntries(settings
  .filter((setting) => setting.type !== 'boolean')
  .map((setting) => {
    if (setting.type === 'integer' || setting.type === 'number') {
      const numeric = Yup.number().typeError(t_i18n('This field must be a number'));
      const base = setting.type === 'integer' ? numeric.integer(t_i18n('This field must be an integer')) : numeric;
      return [setting.key, base.required(t_i18n('This field is required'))];
    }
    // A secret is a credential: its spaces are part of it
    const base = setting.secret ? Yup.string() : Yup.string().trim();
    return [setting.key, base.required(t_i18n('This field is required'))];
  })));

export const deploySettingValues = (settings: readonly DeploySetting[], values: Record<string, string | boolean>) => settings
  .map((setting) => {
    const value = String(values[setting.key]);
    return { key: setting.key, value: setting.secret ? value : value.trim() };
  });
