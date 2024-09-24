import React, { FunctionComponent, ReactNode, useContext } from 'react';
import { IntlProvider } from 'react-intl';
import moment from 'moment';
import { AdapterDateFns } from '@mui/x-date-pickers/AdapterDateFnsV3';
import { LocalizationProvider } from '@mui/x-date-pickers';
import { createFragmentContainer, graphql } from 'react-relay';
import { Locale } from 'date-fns/locale/types';
import { enUS, fr, es, ja, zhCN, de, ko } from 'date-fns/locale';
import locale, { DEFAULT_LANG } from '../utils/BrowserLanguage';
import { UserContext } from '../utils/hooks/useAuth';
import { AppIntlProvider_settings$data } from './__generated__/AppIntlProvider_settings.graphql';
import messages_es_front from '../../lang/front/es.json';
import messages_fr_front from '../../lang/front/fr.json';
import messages_ja_front from '../../lang/front/ja.json';
import messages_zh_front from '../../lang/front/zh.json';
import messages_en_front from '../../lang/front/en.json';
import messages_de_front from '../../lang/front/de.json';
import messages_ko_front from '../../lang/front/ko.json';
import messages_es_back from '../../lang/back/es.json';
import messages_fr_back from '../../lang/back/fr.json';
import messages_ja_back from '../../lang/back/ja.json';
import messages_zh_back from '../../lang/back/zh.json';
import messages_en_back from '../../lang/back/en.json';
import messages_de_back from '../../lang/back/de.json';
import messages_ko_back from '../../lang/back/ko.json';
import { useDocumentLangModifier } from '../utils/hooks/useDocumentModifier';

type PlatformLang = 'es-es' | 'fr-fr' | 'ja-jp' | 'zh-cn' | 'en-us' | 'de-de' | 'ko-kr';

const localeMap: Record<PlatformLang, Locale> = {
  'en-us': enUS,
  'fr-fr': fr,
  'es-es': es,
  'ja-jp': ja,
  'zh-cn': zhCN,
  'de-de': de,
  'ko-kr': ko,
};

const i18n: { messages: Record<PlatformLang, Record<string, string>> } = {
  messages: {
    'es-es': { ...messages_es_back, ...messages_es_front },
    'fr-fr': { ...messages_fr_back, ...messages_fr_front },
    'ja-jp': { ...messages_ja_back, ...messages_ja_front },
    'zh-cn': { ...messages_zh_back, ...messages_zh_front },
    'en-us': { ...messages_en_back, ...messages_en_front },
    'de-de': { ...messages_de_back, ...messages_de_front },
    'ko-kr': { ...messages_ko_back, ...messages_ko_front },
  },
};

export const availableLanguage: { value: PlatformLang, label: string, name: string }[] = [
  { value: 'en-us', label: 'English', name: 'English' },
  { value: 'fr-fr', label: 'Français', name: 'French' },
  { value: 'es-es', label: 'Español', name: 'Spanish' },
  { value: 'ja-jp', label: '日本語', name: 'Japanese' },
  { value: 'zh-cn', label: '简化字', name: 'Chinese' },
  { value: 'de-de', label: 'Deutsch', name: 'German' },
  { value: 'ko-kr', label: '한국어', name: 'Korean' },
];

// list of available languages for Ai text generation (minimal support : platform languages)
export const aiLanguage: { value: string, label: string, name: string }[] = [
  ...availableLanguage,
  // Add new languages which are only supported for ia, not for the platform
];

interface AppIntlProviderProps {
  settings: AppIntlProvider_settings$data | { platform_language: string },
  children: ReactNode,
}

const AppIntlProvider: FunctionComponent<AppIntlProviderProps> = ({ settings, children }) => {
  const { me } = useContext(UserContext);
  const platformLanguage = settings.platform_language ?? null;
  const platformLang = platformLanguage !== null && platformLanguage !== 'auto'
    ? settings.platform_language
    : locale;
  const lang: PlatformLang = me?.language && me.language !== 'auto' ? me.language : platformLang;
  const baseMessages = i18n.messages[lang] || i18n.messages[DEFAULT_LANG as keyof typeof i18n.messages];
  const supportedLocales: PlatformLang[] = availableLanguage.map(({ value }) => value);
  const selectedLocale = supportedLocales.includes(lang) ? lang : 'en-us';
  moment.locale(selectedLocale);
  useDocumentLangModifier(lang.split('-')[0]);
  return (
    <IntlProvider
      locale={lang}
      key={lang}
      messages={baseMessages}
      onError={(err) => {
        if (err.code === 'MISSING_TRANSLATION') {
          return;
        }
        throw err;
      }}
    >
      <LocalizationProvider
        dateAdapter={AdapterDateFns}
        adapterLocale={localeMap[lang]}
      >
        {children}
      </LocalizationProvider>
    </IntlProvider>
  );
};

export const ConnectedIntlProvider = createFragmentContainer(AppIntlProvider, {
  settings: graphql`
    fragment AppIntlProvider_settings on Settings {
      platform_language
    }
  `,
});

export default AppIntlProvider;
