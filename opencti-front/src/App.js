import React, {Component} from 'react';
import logo from './logo.svg';
import './App.css';
import {QueryRenderer} from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import environment from './relay/environment';

const testQuery = graphql`
    query AppUserQuery {
        me {
            id
        }
    }
`;

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
                </header>
                <QueryRenderer
                    environment={environment}
                    query={testQuery}
                    variables={{}}
                    render={({error, props}) => {
                        if (error) {
                            return <div>Error! {error}</div>;
                        }
                        if (!props) {
                            return <div>Loading...</div>;
                        }
                        return <div>User ID: {props.me.id}</div>;
                    }}
                />
            </div>
        );
    }
}

export default App;
