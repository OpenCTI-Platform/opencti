/**
 * Pure utility functions for httpPlatform
 */
import nconf from 'nconf';
import { booleanConf, DEV_MODE } from '../config/conf';

const PUBLIC_AUTH_DOMAINS: string = nconf.get('app:public_dashboard_authorized_domains') ?? '';
export const getPublicAuthorizedDomainsFromConfiguration = () => {
  return PUBLIC_AUTH_DOMAINS.trim();
};

const IS_HTTP_ALLOWED: boolean = booleanConf('app:allow_http_resources', true);
export const isHttpResourceAllowed = () => {
  return IS_HTTP_ALLOWED;
};

export const isDevMode = () => {
  return DEV_MODE;
};

const buildScriptSrc = () => {
  const scriptSrc = ["'self'", "'unsafe-inline'"];
  if (isDevMode()) {
    scriptSrc.push("'unsafe-eval'");
  }
  return scriptSrc;
};

export const buildPublicHelmetParameters = () => {
  const ancestorsFromConfig = getPublicAuthorizedDomainsFromConfiguration();
  const frameAncestorDomains = ancestorsFromConfig === '' ? "'none'" : ancestorsFromConfig;
  const allowedFrameSrc = ["'self'"];
  const imgSrc = ["'self'", 'data:', 'https://*'];
  const manifestSrc = ["'self'", 'data:', 'https://*'];
  const connectSrc = ["'self'", 'wss://*', 'data:', 'https://*'];
  const objectSrc = ["'self'", 'data:', 'https://*'];

  return {
    referrerPolicy: { policy: 'unsafe-url' },
    crossOriginEmbedderPolicy: false,
    crossOriginOpenerPolicy: false,
    crossOriginResourcePolicy: false,
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: buildScriptSrc(),
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrcAttr: ["'none'"],
        fontSrc: ["'self'", 'data:'],
        imgSrc,
        manifestSrc,
        connectSrc,
        objectSrc,
        frameSrc: allowedFrameSrc,
        frameAncestors: frameAncestorDomains,
      },
    },
    xFrameOptions: frameAncestorDomains === "'none'",
  };
};

export const buildDefaultHelmetParameters = () => {
  const imgSrc = ["'self'", 'data:', 'https://*'];
  const manifestSrc = ["'self'", 'data:', 'https://*'];
  const connectSrc = ["'self'", 'wss://*', 'data:', 'https://*'];
  const objectSrc = ["'self'", 'data:', 'https://*'];

  return {
    referrerPolicy: { policy: 'unsafe-url' },
    crossOriginEmbedderPolicy: false,
    crossOriginOpenerPolicy: false,
    crossOriginResourcePolicy: false,
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: buildScriptSrc(),
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrcAttr: ["'none'"],
        fontSrc: ["'self'", 'data:'],
        imgSrc,
        manifestSrc,
        connectSrc,
        objectSrc,
        frameAncestors: "'none'",
      },
    },
  };
};
