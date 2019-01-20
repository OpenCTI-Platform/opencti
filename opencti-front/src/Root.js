import React from 'react';
import { Route, Redirect } from 'react-router-dom';
import Cookies from 'universal-cookie';

export const cookies = new Cookies();

const Root = () => (<Route exact path='/' render={() => (
    <Redirect to='/dashboard'/>
)}/>);

export default Root;
