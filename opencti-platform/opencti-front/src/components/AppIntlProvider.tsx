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
import i18n from '../utils/Localization';
import { UserContext } from '../utils/hooks/useAuth';
import { AppIntlProvider_settings$data } from './__generated__/AppIntlProvider_settings.graphql';

const localeMap = {
  'en-us': enLocale,
  'fr-fr': frLocale,
  'es-es': esLocale,
  'ja-jp': jaLocale,
  'zh-cn': cnLocale,
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
  const lang = (me
    && me.language !== null
    && me.language !== undefined
    && me.language !== 'auto'
    ? me.language
    : platformLang) as ('es-es' | 'fr-fr' | 'ja-jp' | 'zh-cn' | 'en-us');
  const baseMessages = i18n.messages[lang] || i18n.messages[DEFAULT_LANG];
  if (lang === 'fr-fr') {
    moment.locale('fr-fr');
  } else if (lang === 'es-es') {
    moment.locale('es-es');
  } else if (lang === 'ja-jp') {
    moment.locale('ja-jp');
  } else if (lang === 'zh-cn') {
    moment.locale('zh-cn');
  } else {
    moment.locale('en-us');
  }
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
