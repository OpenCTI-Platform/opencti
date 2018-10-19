import React, {Component} from 'react';
import {Link, Redirect, Route} from "react-router-dom";
import {Home} from './components/Home';
import Private from './components/Private';
import {Login} from './components/Login';
import logo from './logo.svg';
import './App.css';
import {identity} from "./index";

const PrivateRoute = ({component: Component, ...rest}) => (
    <Route {...rest} render={(props) => (
        identity() !== null
            ? <Component {...props} />
            : <Redirect to='/login'/>
    )}/>
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
                            <Link to="/private">Private</Link>
                        </li>
                        <li>
                            <a href="/auth/facebook">Facebook</a>
                        </li>
                    </ul>
                    <Route exact path="/" component={Home}/>
                    <Route exact path="/login" component={Login}/>
                    <PrivateRoute exact path="/private" component={Private}/>
                </header>
            </div>
        );
    }
}

export default App;
