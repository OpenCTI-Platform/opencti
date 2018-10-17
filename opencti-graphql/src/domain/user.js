import {driver} from '../database/index';
import {isEmpty, head, contains, map, assoc, compose} from 'ramda';
import {sign} from 'jsonwebtoken';
import conf from '../config/conf';
import moment from 'moment';
import bcrypt from 'bcrypt';
import {pubsub} from "../config/bus";
import {USER_ADDED_TOPIC} from "../resolvers/user";
import uuid from "uuid/v4";

const ROLE_USER = 'ROLE_USER';
const ROLE_ADMIN = 'ROLE_ADMIN';

export const assertUserRole = (user, role) => {
    if (!contains(role, user.roles)) throw new Error("Insufficient privilege");
};

export const assertAdmin = (user) => {
    assertUserRole(user, ROLE_ADMIN)
};

export const loginFromProvider = (email, username) => {
    let session = driver.session();
    const user = {
        id: uuid(),
        username: username,
        email: email,
        roles: [ROLE_USER],
        created_at: moment().toISOString(),
        password: 'oauth'
    };
    let promise = session.run('MERGE (user:User {email: {email}}) ON CREATE SET user = {user} RETURN user',
        {email: email, user: user});
    return promise.then(async (data) => {
        let dbUser = head(data.records).get('user');
        let token = sign(dbUser.properties, conf.get("jwt:secret"));
        session.close();
        return {jwt: token};
    });
};

export const login = (email, password) => {
    let session = driver.session();
    let promise = session.run('MATCH (user:User {email: {email}}) RETURN user', {email: email});
    return promise.then(async (data) => {
        if (isEmpty(data.records)) {
            throw {message: 'login failed', status: 400}
        }
        let dbUser = head(data.records).get('user');
        let dbPassword = dbUser.properties.password;
        const match = await bcrypt.compare(password, dbPassword);
        if (!match) {
            throw {message: 'login failed', status: 400}
        }
        let token = sign(dbUser.properties, conf.get("jwt:secret"));
        session.close();
        return {jwt: token};
    });
};

export const findAll = (first, offset) => {
    let session = driver.session();
    let promise = session.run('MATCH (user:User) RETURN user ORDER BY user.id SKIP {skip} LIMIT {limit}',
        {skip: offset, limit: first});
    return promise.then((data) => {
        session.close();
        return map((record) => record.get('user').properties, data.records);
    });
};

export const findById = (userId) => {
    let session = driver.session();
    let promise = session.run('MATCH (user:User {id: {userId}}) RETURN user', {userId: userId});
    return promise.then((data) => {
        session.close();
        if (isEmpty(data.records)) throw {message: 'Cant find this user', status: 400};
        return head(data.records).get('user').properties;
    });
};

export const addUser = async (user) => {
    let completeUser = compose(
        assoc('created_at', moment().toISOString()),
        assoc('password', await hashPassword(user.password)),
    )(user);
    let session = driver.session();
    let promise = session.run('CREATE (user:User {user}) RETURN user', {user: completeUser});
    return promise.then((data) => {
        session.close();
        let userAdded = head(data.records).get('user').properties;
        pubsub.publish(USER_ADDED_TOPIC, {userAdded: userAdded});
        return userAdded;
    });
};

export const deleteUser = (userId) => {
    let session = driver.session();
    let promise = session.run('MATCH (user:User {id: {userId}}) DELETE user RETURN user', {userId: userId});
    return promise.then((data) => {
        session.close();
        if (isEmpty(data.records)) {
            throw new Error('User doesn\'t exist')
        } else {
            return userId;
        }
    });
};

export const hashPassword = (password) => {
    return bcrypt.hash(password, 10);
};