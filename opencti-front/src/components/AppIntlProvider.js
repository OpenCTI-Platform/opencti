import React, { Component } from 'react';
import { addLocaleData, IntlProvider } from 'react-intl';
import enLocaleData from 'react-intl/locale-data/en';
import frLocaleData from 'react-intl/locale-data/fr';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { pathOr } from 'ramda';
import * as PropTypes from 'prop-types';
import locale from '../utils/BrowserLanguage';
import i18n from '../utils/Localization';

addLocaleData([...enLocaleData, ...frLocaleData]);

class AppIntlProvider extends Component {
  render() {
    const { children } = this.props;
    const lang = pathOr(null, ['me', 'language'], this.props) !== null ? this.props.me.language : locale;
    return <IntlProvider locale={lang} key={lang}
                         messages={i18n.messages[lang]}>{children}</IntlProvider>;
  }
}
AppIntlProvider.propTypes = {
  children: PropTypes.node,
  me: PropTypes.object,
};

export const ConnectedIntlProvider = createFragmentContainer(AppIntlProvider, {
  me: graphql`
        fragment AppIntlProvider_me on User {
            language
        }
    `,
});

export default AppIntlProvider;
