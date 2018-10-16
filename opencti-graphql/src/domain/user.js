import {driver} from '../database/index';
import {isEmpty, head, contains, map} from 'ramda';
import {sign} from 'jsonwebtoken';
import {applicationSecret} from "../server";
import {UnauthorizedError} from "express-jwt";
import uuid from 'uuid/v4';
import moment from 'moment';

const ROLE_ADMIN = 'ROLE_ADMIN';

export const assertUserRole = (user, role) => {
    if (!contains(role, user.roles)) throw new UnauthorizedError(401, new Error("Insufficient privilege"));
};

export const assertAdmin = (user) => {
    assertUserRole(user, ROLE_ADMIN)
};

export const login = (username, password) => {
    let session = driver.session();
    let promise = session.run('MATCH (user:User {username: {username}}) RETURN user', {username: username});
    return promise.then((data) => {
        if (isEmpty(data.records)) {
            throw {message: 'login failed', status: 400}
        }
        let dbUser = head(data.records).get('user');
        let dbPassword = dbUser.properties.password;
        if (password !== dbPassword) {
            throw {message: 'login failed', status: 400}
        }
        let token = sign(dbUser.properties, applicationSecret);
        session.close();
        return {jwt: token};
    });
};

export const findAll = (first, offset) => {
    let session = driver.session();
    let promise = session.run('MATCH (user:User) RETURN user ORDER BY user.id SKIP {skip} LIMIT {limit}',
        {skip: offset, limit: first});
    return promise.then((data) => {
        return map((record) => record.get('user').properties, data.records);
    });
};

export const findById = (userId) => {
    let session = driver.session();
    let promise = session.run('MATCH (user:User {id: {userId}}) RETURN user', {userId: userId});
    return promise.then((data) => {
        if (isEmpty(data.records)) throw {message: 'Cant find this user', status: 400};
        return head(data.records).get('user').properties;
    });
};

export const addUser = (addUserInput) => {
    const user =  {
        id: uuid(),
        username: addUserInput.username,
        email: addUserInput.email,
        created_at: moment().toISOString(),
        roles: ['ROLE_USER']
    };
    let session = driver.session();
    let promise = session.run('CREATE (user:User {user}) RETURN user', {user: user});
    return promise.then((data) => {
        return head(data.records).get('user').properties;
    });
};