import React, {Component} from 'react';
import {addLocaleData, IntlProvider} from 'react-intl'
import enLocaleData from 'react-intl/locale-data/en'
import frLocaleData from 'react-intl/locale-data/fr'
import graphql from 'babel-plugin-relay/macro';
import {QueryRenderer} from 'react-relay'
import {pathOr} from 'ramda'
import {locale} from '../utils/BrowserLanguage'
import {i18n} from "../utils/Localization";
import environment from "../relay/environment";

addLocaleData([...enLocaleData, ...frLocaleData])

const userQuery = graphql`
    query AppIntlProviderQuery {
        me {
            language
        }
    }
`

class AppIntlProvider extends Component {
  render() {
    const {children} = this.props
    return (
      <QueryRenderer environment={environment} query={userQuery} variables={{}} render={({error, props}) => {
        let lang = pathOr(null, ['me', 'lang'], props) !== null ? props.me.lang : locale
        return <IntlProvider locale={lang} key={lang} messages={i18n.messages[lang]}>{children}</IntlProvider>
      }}
      />
    )
  }
}

export default AppIntlProvider