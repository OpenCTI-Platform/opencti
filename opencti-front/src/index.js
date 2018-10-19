import React from 'react';
import ReactDOM from 'react-dom';
import './index.css';
import App from './App';
import * as serviceWorker from './serviceWorker';
import {BrowserRouter} from "react-router-dom";
import {CookiesProvider} from 'react-cookie';
import Cookies from 'universal-cookie';
import jwt from "jsonwebtoken";

const cookies = new Cookies();
export const identity = () => {
    let openctiToken = cookies.get('opencti_token');
    if (openctiToken) {
        let decode = jwt.decode(openctiToken);
        console.log(decode);
        return decode;
    } else {
        return null;
    }
};

ReactDOM.render(
    <BrowserRouter>
        <CookiesProvider>
            <App/>
        </CookiesProvider>
    </BrowserRouter>,
    document.getElementById('root'));

// If you want your app to work offline and load faster, you can change
// unregister() to register() below. Note this comes with some pitfalls.
// Learn more about service workers: http://bit.ly/CRA-PWA
serviceWorker.unregister();
