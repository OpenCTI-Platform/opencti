import React from 'react';
import ReactDOM from 'react-dom';
import './resources/index.css';
import AppPublic from './public/AppPublic';
import * as serviceWorker from './config/serviceWorker';
import {BrowserRouter, Redirect, Route} from "react-router-dom";
import Cookies from 'universal-cookie';
import jwt from "jsonwebtoken";
import AppPrivate from "./private/AppPrivate";

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
    let openctiToken = cookies.get('opencti_token');
    if (openctiToken) {
        let decode = jwt.decode(openctiToken);
        return decode !== undefined;
    } else {
        return false;
    }
};

const PrivateRoute = ({component: Component, ...rest}) => (
    <Route {...rest} render={(props) => (
        isLogged() ? <Component {...props} /> : <Redirect to='/public/login'/>
    )}/>
);

ReactDOM.render(
    <BrowserRouter>
        <div>
            <Route exact path='/' component={AppPublic}/>
            <Route path='/public' component={AppPublic}/>
            <PrivateRoute path="/private" component={AppPrivate}/>
        </div>
    </BrowserRouter>,
    document.getElementById('root'));

// If you want your app to work offline and load faster, you can change
// unregister() to register() below. Note this comes with some pitfalls.
// Learn more about service workers: http://bit.ly/CRA-PWA
serviceWorker.unregister();
