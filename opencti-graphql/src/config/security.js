import passport from "passport/lib";
import LocalStrategy from "passport-local";
import FacebookStrategy from "passport-facebook";
import {OAuth2Strategy as GoogleStrategy} from "passport-google-oauth";
import {login, loginFromProvider} from "../domain/user";
import conf from '../config/conf';
import {head} from "ramda";

passport.use(
    new LocalStrategy(
        function (username, password, done) {
            login(username, password)
                .then((token) => done(null, token))
                .catch(() => done(null, false, {message: 'Incorrect login or password.'}));
        }
    ));

passport.use(
    new FacebookStrategy({
            clientID: conf.get("providers:facebook:client_id"),
            clientSecret: conf.get("providers:facebook:client_secret"),
            callbackURL: conf.get("providers:facebook:callback_uri"),
            profileFields: ['id', 'emails', 'name']
        }, function (accessToken, refreshToken, profile, done) {
            let data = profile._json;
            let username = data.last_name + ' ' + data.first_name;
            let email = data.email;
            loginFromProvider(email, username).then((token) => {
                done(null, token);
            }).catch((err) => {
                done(err);
            });
        }
    ));

passport.use(
    new GoogleStrategy({
            clientID: conf.get("providers:google:client_id"),
            clientSecret: conf.get("providers:google:client_secret"),
            callbackURL: conf.get("providers:google:callback_uri")
        },
        function (token, tokenSecret, profile, done) {
            let username = profile.displayName;
            let email = head(profile.emails).value;
            //let picture = head(profile.photos).value;
            loginFromProvider(email, username).then((token) => {
                done(null, token);
            }).catch((err) => {
                done(err);
            });
        }
    ));

export default passport;