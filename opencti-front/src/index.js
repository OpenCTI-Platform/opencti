import 'typeface-roboto'
import React from 'react'
import ReactDOM from 'react-dom'
import {addLocaleData, IntlProvider} from 'react-intl'
import enLocaleData from 'react-intl/locale-data/en'
import frLocaleData from 'react-intl/locale-data/fr'
import './resources/css/index.css'
import * as serviceWorker from './config/serviceWorker'
import {BrowserRouter, Redirect, Route} from 'react-router-dom'
import Cookies from 'universal-cookie'
import jwt from 'jsonwebtoken'
import MuiThemeProvider from '@material-ui/core/styles/MuiThemeProvider'
import CssBaseline from '@material-ui/core/CssBaseline'
import {createMuiTheme} from '@material-ui/core/styles'
import theme from './components/Theme'
import {i18n} from './utils/Localization'
import Root from './Root'
import Login from './public/components/Login'
import RootPrivate from './private/Root'

//Loading application
/*
commitLocalUpdate(environment, (store) => {
    let openctiToken = cookies.get('opencti_token');
    const id = 'user_auth_id';
    let authentication = store.create(id, 'User');
    authentication.setValue(id, 'id');
    if(openctiToken) {
        let record = jwt.decode(openctiToken);
        const keys = Object.keys(record);
        for (let ii = 0; ii < keys.length; ii++) {
            const key = keys[ii];
            const val = record[key];
            authentication.setValue(val, key);
        }
    } else {
        store.delete(id);
    }
});
*/

const isLogged = () => {
    const cookies = new Cookies();
    let openctiToken = cookies.get('opencti_token')
    if (openctiToken) {
        let decode = jwt.decode(openctiToken)
        return decode !== undefined
    } else {
        return false
    }
}

const PrivateRoute = ({component: Component, ...rest}) => (
    <Route {...rest} render={(props) => (
        isLogged() ? <Component {...props} /> : <Redirect to='/login'/>
    )}/>
)

addLocaleData([...enLocaleData, ...frLocaleData])

ReactDOM.render(
    <IntlProvider locale='en' key='en' messages={i18n.messages['en']}>
        <MuiThemeProvider theme={createMuiTheme(theme)}>
            <BrowserRouter>
                <div>
                    <CssBaseline/>
                    <Route exact path='/' component={Root}/>
                    <Route path='/login' component={Login}/>
                    <PrivateRoute path='/dashboard' component={RootPrivate}/>
                </div>
            </BrowserRouter>
        </MuiThemeProvider>
    </IntlProvider>,
    document.getElementById('root'))

// If you want your app to work offline and load faster, you can change
// unregister() to register() below. Note this comes with some pitfalls.
// Learn more about service workers: http://bit.ly/CRA-PWA
serviceWorker.unregister()
