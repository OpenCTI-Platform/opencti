import React from 'react';
import ReactDOM from 'react-dom';
import './index.css';
import AppPublic from './AppPublic';
import * as serviceWorker from './serviceWorker';
import {BrowserRouter, Redirect, Route} from "react-router-dom";
import Cookies from 'universal-cookie';
import jwt from "jsonwebtoken";
import AppPrivate from "./components/Private";

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
        isLogged() ? <Component {...props} /> : <Redirect to='/login'/>
    )}/>
);

ReactDOM.render(
    <BrowserRouter>
        <div>
            <Route path='/' component={AppPublic}/>
            <PrivateRoute path="/private" component={AppPrivate}/>
        </div>
    </BrowserRouter>,
    document.getElementById('root'));

// If you want your app to work offline and load faster, you can change
// unregister() to register() below. Note this comes with some pitfalls.
// Learn more about service workers: http://bit.ly/CRA-PWA
serviceWorker.unregister();
