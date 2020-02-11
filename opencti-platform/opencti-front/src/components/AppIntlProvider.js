import React, { useContext } from 'react';
import * as PropTypes from 'prop-types';
import { IntlProvider } from 'react-intl';
import MomentUtils from '@date-io/moment';
import 'moment/locale/fr';
import moment from 'moment';
import { MuiPickersUtilsProvider } from '@material-ui/pickers';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { pathOr } from 'ramda';
import locale from '../utils/BrowserLanguage';
import i18n from '../utils/Localization';
import { UserContext } from '../utils/Security';

const AppIntlProvider = (props) => {
  const { children } = props;
  const me = useContext(UserContext);
  const intlError = (error) => {
    const matchingLocale = /for locale: "([a-z]+)"/gm;
    const regMatch = matchingLocale.exec(error);
    const currentLocale = regMatch !== null ? regMatch[1] : null;
    if (currentLocale && currentLocale !== 'en') console.error(error);
  };
  const platformLanguage = pathOr(
    null,
    ['settings', 'platform_language'],
    props,
  );
  const platformLang = platformLanguage !== null && platformLanguage !== 'auto'
    ? props.settings.platform_language
    : locale;
  const lang = me.language !== null && me.language !== undefined && me.language !== 'auto'
    ? me.language
    : platformLang;
  return (
      <IntlProvider locale={lang} onError={intlError} key={lang} messages={i18n.messages[lang]}>
        <MuiPickersUtilsProvider
          utils={MomentUtils}
          locale={lang}
          moment={moment}>
          {children}
        </MuiPickersUtilsProvider>
      </IntlProvider>
  );
};

AppIntlProvider.propTypes = {
  children: PropTypes.node,
  settings: PropTypes.object,
};

export const ConnectedIntlProvider = createFragmentContainer(AppIntlProvider, {
  settings: graphql`
    fragment AppIntlProvider_settings on Settings {
      platform_language
    }
  `,
});

export default AppIntlProvider;
