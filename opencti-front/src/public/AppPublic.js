import React, {Component} from 'react';
import {Link, Route} from "react-router-dom";
import logo from '../resources/logo.svg';
import '../resources/App.css';
import {Home} from "./components/Home";
import {Login} from "./components/Login";

class AppPublic extends Component {
    render() {
        return (
            <div className="App">
                <header className="App-header">
                    <img src={logo} className="App-logo" alt="logo"/>
                    <p>PUBLIC ZONE</p>
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
                    </ul>
                </header>
                <div>
                    <Route exact path="/" component={Home}/>
                    <Route path="/public/login" component={Login}/>
                </div>
            </div>
        );
    }
}

export default AppPublic;
