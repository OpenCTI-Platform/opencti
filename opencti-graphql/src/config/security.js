import passport from 'passport/lib';
import LocalStrategy from 'passport-local';
import FacebookStrategy from 'passport-facebook';
import GithubStrategy from 'passport-github';
import { OAuth2Strategy as GoogleStrategy } from 'passport-google-oauth';
import { head } from 'ramda';
import { login, loginFromProvider } from '../domain/user';
import conf from './conf';

// Local auth
const localStrategy = new LocalStrategy((username, password, done) => {
  login(username, password)
    .then(token => done(null, token))
    .catch(err => done(err));
});
// Facebook
const facebookOptions = {
  clientID: conf.get('providers:facebook:client_id'),
  clientSecret: conf.get('providers:facebook:client_secret'),
  callbackURL: conf.get('providers:facebook:callback_uri'),
  profileFields: ['id', 'emails', 'name'],
  scope: 'email'
};
const facebookStrategy = new FacebookStrategy(
  facebookOptions,
  (accessToken, refreshToken, profile, done) => {
    // eslint-disable-next-line no-underscore-dangle
    const data = profile._json; // TODO CHECK THAT
    const username = `${data.last_name} ${data.first_name}`;
    const { email } = data;
    loginFromProvider(email, username)
      .then(token => {
        done(null, token);
      })
      .catch(err => {
        done(err);
      });
  }
);
// Google
const googleOptions = {
  clientID: conf.get('providers:google:client_id'),
  clientSecret: conf.get('providers:google:client_secret'),
  callbackURL: conf.get('providers:google:callback_uri'),
  scope: 'email'
};
const googleStrategy = new GoogleStrategy(
  googleOptions,
  (token, tokenSecret, profile, done) => {
    const username = profile.displayName;
    const email = head(profile.emails).value;
    // let picture = head(profile.photos).value;
    loginFromProvider(email, username)
      .then(loggedToken => {
        done(null, loggedToken);
      })
      .catch(err => {
        done(err);
      });
  }
);
// Github
const githubOptions = {
  clientID: conf.get('providers:github:client_id'),
  clientSecret: conf.get('providers:github:client_secret'),
  callbackURL: conf.get('providers:github:callback_uri'),
  scope: 'user:email'
};
const githubStrategy = new GithubStrategy(
  githubOptions,
  (token, tokenSecret, profile, done) => {
    const username = profile.name;
    const email = head(profile.emails).value;
    // let picture = profile.avatar_url;
    loginFromProvider(email, username)
      .then(loggedToken => {
        done(null, loggedToken);
      })
      .catch(err => {
        done(err);
      });
  }
);

// Register strategies
passport.use(localStrategy);
passport.use(facebookStrategy);
passport.use(googleStrategy);
passport.use(githubStrategy);

export default passport;
