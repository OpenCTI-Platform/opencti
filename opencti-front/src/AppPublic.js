import React, {Component} from 'react';
import {Link, Route} from "react-router-dom";
import logo from './logo.svg';
import './App.css';
import {Login} from "./components/Login";
import {Home} from "./components/Home";

class AppPublic extends Component {
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
                </header>
                <div>
                    <Route path="/login" component={Login}/>
                    <Route exact path="/" component={Home}/>
                </div>
            </div>
        );
    }
}

export default AppPublic;
