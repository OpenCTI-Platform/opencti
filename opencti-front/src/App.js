import React, {Component} from 'react';
import {Route, Link, Redirect} from "react-router-dom";
import {Home} from './components/Home';
import {About} from './components/About';
import {Login} from './components/Login';
import logo from './logo.svg';
import './App.css';

const PrivateRoute = ({component: Component, ...rest}) => (
    <Route {...rest} render={props =>
        props.isAuthenticated ? (
            <Component {...props} />) : (
            <Redirect to={{pathname: "/login", state: {from: props.location}}}/>
        )
    }/>
);

class App extends Component {
    render() {
        return (
            <div className="App">
                <header className="App-header">
                    <img src={logo} className="App-logo" alt="logo"/>
                    <p>
                        Edit <code>src/App.js</code> and save to reload.
                    </p>
                    <a className="App-link"
                       href="https://reactjs.org"
                       target="_blank"
                       rel="noopener noreferrer">
                        Learn React
                    </a>
                    <ul>
                        <li>
                            <Link to="/">Home</Link>
                        </li>
                        <li>
                            <Link to="/about">About</Link>
                        </li>
                    </ul>
                    <Route exact path="/" component={Home}/>
                    <Route exact path="/login" component={Login}/>
                    <PrivateRoute path="/about" component={About}/>
                </header>
            </div>
        );
    }
}

export default App;
