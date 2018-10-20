import {driver} from '../database/index';
import {assoc, compose, contains, head, isEmpty, map} from 'ramda';
import moment from 'moment';
import bcrypt from 'bcrypt';
import {pubsub} from "../config/bus";
import {USER_ADDED_TOPIC} from "../resolvers/user";
import uuid from "uuid/v4";
import uuidv5 from "uuid/v5";

const OPENCTI_WEB_TOKEN = 'Default';
const ROLE_USER = 'ROLE_USER';
const ROLE_ADMIN = 'ROLE_ADMIN';

//Security related
export const assertUserRole = (user, role) => {
    if (!contains(role, user.roles)) throw new Error("Insufficient privilege");
};

export const assertAdmin = (user) => {
    assertUserRole(user, ROLE_ADMIN)
};

//User related
export const loginFromProvider = (email, username) => {
    let session = driver.session();
    const user = {
        id: uuid(),
        username: username,
        email: email,
        roles: [ROLE_USER],
        created_at: moment().toISOString(),
        password: null
    };
    let token = generateOpenCTIWebToken(email);
    let promise = session.run(
        'MERGE (user:User {email: {user}.email}) ON CREATE SET user = {user} ' +
        'MERGE (user)<-[:WEB_ACCESS]-(token:Token {name: {token}.name}) ON CREATE SET token = {token} ' +
        'RETURN token', {user: user, token: token});
    return promise.then(async (data) => {
        session.close();
        if (isEmpty(data.records)) {
            throw {message: 'login failed', status: 400}
        }
        return head(data.records).get('token').properties;
    });
};

export const login = (email, password) => {
    let session = driver.session();
    let promise = session.run('MATCH (user:User {email: {email}})<-[:WEB_ACCESS]-(token:Token) RETURN user, token', {email: email});
    return promise.then(async (data) => {
        session.close();
        if (isEmpty(data.records)) {
            throw {message: 'login failed', status: 400}
        }
        let firstRecord = head(data.records);
        let dbUser = firstRecord.get('user');
        let dbPassword = dbUser.properties.password;
        const match = await bcrypt.compare(password, dbPassword);
        if (!match) {
            throw {message: 'login failed', status: 400}
        }
        return firstRecord.get('token').properties;
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
    let promise = session.run('CREATE (user:User {user})<-[:WEB_ACCESS]-(token:Token {token}) RETURN user',
        {user: completeUser, token: generateOpenCTIWebToken(user.email)});
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

//Token related
const generateOpenCTIWebToken = (email) => {
    return {
        id: uuidv5(email, uuidv5.URL),
        name: OPENCTI_WEB_TOKEN,
        created_at: moment().toISOString(),
        issuer: 'OpenCTI',
        revoked: false,
        duration: 'P99Y' //99 years per default
    };
};

export const findByTokenId = (tokenId) => {
    let session = driver.session();
    //Fetch user by token relation if the token is not revoked
    let promise = session.run('MATCH (token:Token {id: {tokenId}, revoked: false})-->(user) RETURN user, token', {tokenId: tokenId});
    return promise.then((data) => {
        session.close();
        if (isEmpty(data.records)) throw {message: 'User token invalid: ' + tokenId, status: 400};
        //Token duration validation
        let record = head(data.records);
        let token = record.get('token').properties;
        let creation = moment(token.created_at);
        let maxDuration = moment.duration(token.duration);
        let now = moment();
        let currentDuration = moment.duration(now.diff(creation));
        if (currentDuration > maxDuration) throw {message: 'User token invalid: ' + tokenId, status: 400};
        return record.get('user').properties;
    });
};