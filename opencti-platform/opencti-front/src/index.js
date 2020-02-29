import 'typeface-roboto';
import React from 'react';
import ReactDOM from 'react-dom';
import './resources/css/index.css';
import 'storm-react-diagrams/dist/style.min.css';
import 'react-grid-layout/css/styles.css';
import * as serviceWorker from './config/serviceWorker';
import App from './app';

ReactDOM.render(<App />, document.getElementById('root'));

// If you want your app to work offline and load faster, you can change
// unregister() to register() below. Note this comes with some pitfalls.
// Learn more about service workers: http://bit.ly/CRA-PWA
serviceWorker.unregister();
