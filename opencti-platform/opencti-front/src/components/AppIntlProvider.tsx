import React, { FunctionComponent, ReactNode, useContext } from 'react';
import { IntlProvider } from 'react-intl';
import moment from 'moment';
import { AdapterDateFns } from '@mui/x-date-pickers/AdapterDateFnsV3';
import { LocalizationProvider } from '@mui/x-date-pickers';
import { createFragmentContainer, graphql } from 'react-relay';
import { Locale } from 'date-fns/locale/types';
import { de, enUS, es, fr, it, ja, ko, zhCN, ru } from 'date-fns/locale';
import locale, { DEFAULT_LANG } from '../utils/BrowserLanguage';
import { UserContext } from '../utils/hooks/useAuth';
import { AppIntlProvider_settings$data } from './__generated__/AppIntlProvider_settings.graphql';
import messages_de_front from '../../lang/front/de.json';
import messages_en_front from '../../lang/front/en.json';
import messages_es_front from '../../lang/front/es.json';
import messages_fr_front from '../../lang/front/fr.json';
import messages_it_front from '../../lang/front/it.json';
import messages_ja_front from '../../lang/front/ja.json';
import messages_ko_front from '../../lang/front/ko.json';
import messages_zh_front from '../../lang/front/zh.json';
import messages_ru_front from '../../lang/front/ru.json';
import messages_de_back from '../../lang/back/de.json';
import messages_en_back from '../../lang/back/en.json';
import messages_es_back from '../../lang/back/es.json';
import messages_fr_back from '../../lang/back/fr.json';
import messages_it_back from '../../lang/back/it.json';
import messages_ja_back from '../../lang/back/ja.json';
import messages_ko_back from '../../lang/back/ko.json';
import messages_zh_back from '../../lang/back/zh.json';
import messages_ru_back from '../../lang/back/ru.json';

import { useDocumentLangModifier } from '../utils/hooks/useDocumentModifier';

type PlatformLang =
  | 'de-de'
  | 'en-us'
  | 'es-es'
  | 'fr-fr'
  | 'it-it'
  | 'ja-jp'
  | 'ko-kr'
  | 'zh-cn'
  | 'ru-ru';

const localeMap: Record<PlatformLang, Locale> = {
  'de-de': de,
  'en-us': enUS,
  'es-es': es,
  'fr-fr': fr,
  'it-it': it,
  'ja-jp': ja,
  'ko-kr': ko,
  'zh-cn': zhCN,
  'ru-ru': ru,
};

const i18n: { messages: Record<PlatformLang, Record<string, string>> } = {
  messages: {
    'de-de': { ...messages_de_back, ...messages_de_front },
    'en-us': { ...messages_en_back, ...messages_en_front },
    'es-es': { ...messages_es_back, ...messages_es_front },
    'fr-fr': { ...messages_fr_back, ...messages_fr_front },
    'it-it': { ...messages_it_back, ...messages_it_front },
    'ja-jp': { ...messages_ja_back, ...messages_ja_front },
    'ko-kr': { ...messages_ko_back, ...messages_ko_front },
    'zh-cn': { ...messages_zh_back, ...messages_zh_front },
    'ru-ru': { ...messages_ru_back, ...messages_ru_front },
  },
};

export const availableLanguage: { value: PlatformLang; label: string; name: string }[] = [
  { value: 'de-de', label: 'Deutsch', name: 'German' },
  { value: 'en-us', label: 'English', name: 'English' },
  { value: 'es-es', label: 'Español', name: 'Spanish' },
  { value: 'fr-fr', label: 'Français', name: 'French' },
  { value: 'it-it', label: 'Italiano', name: 'Italian' },
  { value: 'ja-jp', label: '日本語', name: 'Japanese' },
  { value: 'ko-kr', label: '한국어', name: 'Korean' },
  { value: 'zh-cn', label: '简化字', name: 'Chinese' },
  { value: 'ru-ru', label: 'Русский', name: 'Russian' },
];

// list of available languages for Ai text generation (minimal support : platform languages)
export const aiLanguage: { value: string; label: string; name: string }[] = [
  ...availableLanguage,
  // Add new languages which are only supported for ia, not for the platform
];

interface AppIntlProviderProps {
  settings: AppIntlProvider_settings$data | { platform_language: string; platform_translations: string };
  children: ReactNode;
}

const AppIntlProvider: FunctionComponent<AppIntlProviderProps> = ({ settings, children }) => {
  const { me } = useContext(UserContext);
  const platformLanguage = settings.platform_language ?? null;
  const platformLang = platformLanguage !== null && platformLanguage !== 'auto' ? settings.platform_language : locale;
  const lang: PlatformLang = me?.language && me.language !== 'auto' ? (me.language as PlatformLang) : (platformLang as PlatformLang);
  const translation = JSON.parse(settings.platform_translations ?? '{}');
  const baseMessages = i18n.messages[lang] || i18n.messages[DEFAULT_LANG as keyof typeof i18n.messages];
  const messages = { ...baseMessages, ...(translation[lang] ?? {}) };
  const supportedLocales: PlatformLang[] = availableLanguage.map(({ value }) => value);
  const selectedLocale = supportedLocales.includes(lang) ? lang : 'en-us';
  moment.locale(selectedLocale);
  useDocumentLangModifier(lang.split('-')[0]);
  return (
    <IntlProvider
      locale={lang}
      key={lang}
      messages={messages}
      onError={(err) => {
        if (err.code === 'MISSING_TRANSLATION') {
          return;
        }
        throw err;
      }}
    >
      <LocalizationProvider dateAdapter={AdapterDateFns} adapterLocale={localeMap[lang]}>
        {children}
      </LocalizationProvider>
    </IntlProvider>
  );
};

export const ConnectedIntlProvider = createFragmentContainer(AppIntlProvider, {
  settings: graphql`
    fragment AppIntlProvider_settings on IntlSettings {
      platform_language
      platform_translations
    }
  `,
});

export default AppIntlProvider;
