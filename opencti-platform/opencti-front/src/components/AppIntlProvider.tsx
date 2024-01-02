import React, { FunctionComponent, ReactNode, useContext } from 'react';
import { IntlProvider } from 'react-intl';
import frLocale from 'date-fns/locale/fr';
import esLocale from 'date-fns/locale/es';
import enLocale from 'date-fns/locale/en-US';
import jaLocale from 'date-fns/locale/ja';
import cnLocale from 'date-fns/locale/zh-CN';
import moment from 'moment';
import { AdapterDateFns } from '@mui/x-date-pickers/AdapterDateFns';
import { LocalizationProvider } from '@mui/x-date-pickers';
import { createFragmentContainer, graphql } from 'react-relay';
import locale, { DEFAULT_LANG } from '../utils/BrowserLanguage';
import { UserContext } from '../utils/hooks/useAuth';
import { AppIntlProvider_settings$data } from './__generated__/AppIntlProvider_settings.graphql';
import messages_es from '../../lang/es.json';
import messages_fr from '../../lang/fr.json';
import messages_ja from '../../lang/ja.json';
import messages_zh from '../../lang/zh.json';
import messages_en from '../../lang/en.json';

type PlatformLang = 'es-es' | 'fr-fr' | 'ja-jp' | 'zh-cn' | 'en-us';
const localeMap = {
  'en-us': enLocale,
  'fr-fr': frLocale,
  'es-es': esLocale,
  'ja-jp': jaLocale,
  'zh-cn': cnLocale,
};

const i18n = {
  messages: {
    'es-es': messages_es,
    'fr-fr': messages_fr,
    'ja-jp': messages_ja,
    'zh-cn': messages_zh,
    'en-us': messages_en,
  },
};

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

  const supportedLocales: PlatformLang[] = ['es-es', 'fr-fr', 'ja-jp', 'zh-cn', 'en-us'];
  const selectedLocale = supportedLocales.includes(lang) ? lang : 'en-us';

  moment.locale(selectedLocale);
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
