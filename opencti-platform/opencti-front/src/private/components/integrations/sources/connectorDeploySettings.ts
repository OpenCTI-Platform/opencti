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

// The catalog reads an integer setting with parseInt: a value validated in another notation (1e3, 0x10, 1 000) is sent
// as the decimal number it stands for, parsed as the validation parses it (spaces removed, then the number it reads)
const decimalNotation = (type: string, value: string) => {
  const compact = value.replace(/\s/g, '');
  const numeric = +compact;
  if (compact === '' || !Number.isFinite(numeric)) {
    return value.trim();
  }
  return type === 'integer' && Number.isInteger(numeric) ? BigInt(numeric).toString() : String(numeric);
};

export const deploySettingValues = (settings: readonly DeploySetting[], values: Record<string, string | boolean>) => settings
  .map((setting) => {
    const value = String(values[setting.key]);
    if (setting.type === 'integer' || setting.type === 'number') {
      return { key: setting.key, value: decimalNotation(setting.type, value) };
    }
    return { key: setting.key, value: setting.secret ? value : value.trim() };
  });
