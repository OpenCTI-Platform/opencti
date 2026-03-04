import { addProxyToClient } from 'aws-sdk-v3-proxy';
import type { HttpHandlerOptions, RequestHandler } from '@aws-sdk/types';
import { getDefaultRoleAssumerWithWebIdentity } from '@aws-sdk/client-sts';
import conf, { booleanConf } from '../config/conf';

type ConfigWithRequestHandler = {
  requestHandler: RequestHandler<any, any, HttpHandlerOptions>;
};

type ClientWithConfig<T> = T extends { config: ConfigWithRequestHandler } ? T : never;

const proxyOptions = booleanConf('aws:proxy_enabled', false)
  ? {
      httpProxy: conf.get('http_proxy'),
      httpsProxy: conf.get('https_proxy'),
    }
  : undefined;

export const setupAwsClient = <T>(client: ClientWithConfig<T>) => {
  return proxyOptions ? addProxyToClient(client, proxyOptions) : client;
};

const addProxyToConfiguration = <T>(config: T) => {
  if (proxyOptions) {
    // aws-sdk-v3-proxy only works on client and doesn't permit to enrich directly a configuration.
    // We create a fake client to be able to let it configured by addProxyToClient and then return the updated configuration.

    // The cast is safe since aws-sdk-v3-proxy doesn't read 'requestHandler' in the configuration and only need to be able to set it
    const fakeClient = { config: (config ?? {}) as ConfigWithRequestHandler };
    return addProxyToClient(fakeClient, proxyOptions).config;
  }
  return config;
};

export const getRoleAssumerWithWebIdentity = (stsOptions?: Parameters<typeof getDefaultRoleAssumerWithWebIdentity>[0]) => {
  return getDefaultRoleAssumerWithWebIdentity(addProxyToConfiguration(stsOptions));
};
