import React from 'react';
import { Route, Redirect } from 'react-router-dom';

const Root = () => (<Route exact path='/' render={() => (
    <Redirect to='/dashboard'/>
)}/>);

export default Root;
