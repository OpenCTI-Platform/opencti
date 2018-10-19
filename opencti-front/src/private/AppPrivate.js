import React, {Component} from "react";
import graphql from "babel-plugin-relay/macro";
import Cookies from "universal-cookie";
import {Link, Route} from "react-router-dom";
import {Home} from "../private/components/Home";
import logo from "../resources/logo.svg";
import {Users} from "./components/Users";
import {withRouter} from 'react-router-dom'
import environment from "../relay/environment";
import {QueryRenderer} from 'react-relay';

const testQuery = graphql`
    query AppPrivateUserQuery {
        me {
            email
            roles
        }
    }
`;

class AppPrivate extends Component {

    callLogout() {
        //Call graphQL mutation logout to remove the token
        new Cookies().remove('opencti_token');
        this.props.history.push('/');
    }

    render() {
        return (
            <div className="App">
                <header className="App-header">
                    <img src={logo} className="App-logo" alt="logo"/>
                    <QueryRenderer
                        environment={environment}
                        query={testQuery}
                        variables={{}}
                        render={({error, props}) => {
                            if (error) {
                                return <div>Error! {error}</div>;
                            }
                            if (!props || !props.me) {
                                return <div>Loading...</div>;
                            }
                            return <div>
                                Yop {props.me.email}
                                <button onClick={this.callLogout.bind(this)}>Logout</button>
                            </div>
                        }}
                    />
                    <p>PRIVATE ZONE</p>
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
                            <Link to="/private">Private zone</Link>
                        </li>
                        <li>
                            <Link to="/private/users">Users</Link>
                        </li>
                    </ul>
                </header>
                <div>
                    <Route exact path="/private" component={Home}/>
                    <Route exact path="/private/users" component={Users}/>
                </div>
            </div>
        )
    }
}

export default withRouter(AppPrivate);