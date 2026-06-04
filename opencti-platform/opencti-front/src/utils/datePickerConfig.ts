import type { PlatformLang } from './hooks/useAuth';

export const JALALI_LOCALE: PlatformLang = 'fa-ir';

/** Display format for MUI DatePicker when using the Jalali adapter. */
export const JALALI_DATE_FORMAT = 'yyyy/MM/dd';

export const isJalaliLocale = (locale: string): locale is PlatformLang => locale === JALALI_LOCALE;

export const resolveDatePickerFormat = (
  locale: string,
  format?: string,
): string | undefined => {
  if (format) {
    return format;
  }
  return isJalaliLocale(locale) ? JALALI_DATE_FORMAT : undefined;
};
