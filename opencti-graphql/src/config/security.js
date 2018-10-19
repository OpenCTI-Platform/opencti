import passport from "passport/lib";
import LocalStrategy from "passport-local";
import FacebookStrategy from "passport-facebook";
import GithubStrategy from "passport-github";
import {OAuth2Strategy as GoogleStrategy} from "passport-google-oauth";
import {login, loginFromProvider} from "../domain/user";
import conf from '../config/conf';
import {head} from "ramda";

//Local auth
let localStrategy = new LocalStrategy(function (username, password, done) {
    login(username, password)
        .then((token) => done(null, token))
        .catch(() => done(null, false, {message: 'Incorrect login or password.'}));
});
//Facebook
let facebookOptions = {
    clientID: conf.get("providers:facebook:client_id"),
    clientSecret: conf.get("providers:facebook:client_secret"),
    callbackURL: conf.get("providers:facebook:callback_uri"),
    profileFields: ['id', 'emails', 'name']
};
let facebookStrategy = new FacebookStrategy(facebookOptions, function (accessToken, refreshToken, profile, done) {
    let data = profile._json;
    let username = data.last_name + ' ' + data.first_name;
    let email = data.email;
    loginFromProvider(email, username).then((token) => {
        done(null, token);
    }).catch((err) => {
        done(err);
    });
});
//Google
let googleOptions = {
    clientID: conf.get("providers:google:client_id"),
    clientSecret: conf.get("providers:google:client_secret"),
    callbackURL: conf.get("providers:google:callback_uri")
};
let googleStrategy = new GoogleStrategy(googleOptions, function (token, tokenSecret, profile, done) {
    let username = profile.displayName;
    let email = head(profile.emails).value;
    //let picture = head(profile.photos).value;
    loginFromProvider(email, username).then((token) => {
        done(null, token);
    }).catch((err) => {
        done(err);
    });
});
//Github
let githubOptions = {
    clientID: conf.get("providers:github:client_id"),
    clientSecret: conf.get("providers:github:client_secret"),
    callbackURL: conf.get("providers:github:callback_uri"),
    scope: 'user:email'
};
let githubStrategy = new GithubStrategy(githubOptions, function (token, tokenSecret, profile, done) {
    let username = profile.name;
    let email = head(profile.emails).value;
    //let picture = profile.avatar_url;
    loginFromProvider(email, username).then((token) => {
        done(null, token);
    }).catch((err) => {
        done(err);
    });
});

//Register strategies
passport.use(localStrategy);
passport.use(facebookStrategy);
passport.use(googleStrategy);
passport.use(githubStrategy);

export default passport;