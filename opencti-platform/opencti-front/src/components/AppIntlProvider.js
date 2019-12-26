import React, { Component } from 'react';
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

class AppIntlProvider extends Component {
  render() {
    const { children } = this.props;
    const platformLanguage = pathOr(
      null,
      ['settings', 'platform_language'],
      this.props,
    );
    const userLanguage = pathOr(null, ['me', 'language'], this.props);
    const platformLang = platformLanguage !== null && platformLanguage !== 'auto'
      ? this.props.settings.platform_language
      : locale;
    const lang = userLanguage !== null && userLanguage !== 'auto'
      ? this.props.me.language
      : platformLang;
    return (
      <IntlProvider locale={lang} key={lang} messages={i18n.messages[lang]}>
        <MuiPickersUtilsProvider
          utils={MomentUtils}
          locale={lang}
          moment={moment}>
          {children}
        </MuiPickersUtilsProvider>
      </IntlProvider>
    );
  }
}

AppIntlProvider.propTypes = {
  children: PropTypes.node,
  me: PropTypes.object,
  settings: PropTypes.object,
};

export const ConnectedIntlProvider = createFragmentContainer(AppIntlProvider, {
  me: graphql`
    fragment AppIntlProvider_me on User {
      language
    }
  `,
  settings: graphql`
    fragment AppIntlProvider_settings on Settings {
      platform_language
    }
  `,
});

export default AppIntlProvider;
