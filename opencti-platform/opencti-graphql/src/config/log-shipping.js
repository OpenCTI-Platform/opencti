import { format } from 'winston';
import GelfTransport from 'winston-gelf';

/**
 * Create a new log shipping transport.
 * @param {Object} conf The transport configuration
 * @param {string} conf.logs_shipping_level The minimum log level of messages to send to ship
 * @param {string} conf.logs_shipping_env_var_prefix The prefix used to match environment variables. Matching
 *     variables will be added as meta info to the log data. The value of this property will be stripped from the name
 *     of the environment variable.
 * @param {string} conf.logs_graylog_host The Graylog host to connect to
 * @param {number} conf.logs_graylog_port The port to use when connecting to the Graylog host
 * @param {'tcp'|'udp'} conf.logs_graylog_adapter The adapter (udp/tcp) to use when connecting to the Graylog host
 * @returns {import('winston-gelf')} The newly created log shipping transport
 */
export function createLogShippingTransport(conf) {
  return new GelfTransport({
    level: conf.logs_shipping_level,
    format: format.combine(
      envVarsFormat(conf.logs_shipping_env_var_prefix)(),
      format.json(),
    ),
    gelfPro: {
      adapterName: `${conf.logs_graylog_adapter}.js`, // append '.js', as a workaround for https://github.com/evanw/esbuild/issues/3328
      adapterOptions: {
        host: conf.logs_graylog_host,
        port: conf.logs_graylog_port,
      },
    },
  });
}

function envVarsFormat(prefix) {
  const envVars = findPrefixedEnvVars(prefix);

  return format(
    (info) => ({ ...info, ...envVars })
  );
}

function findPrefixedEnvVars(prefix) {
  return Object.fromEntries(
    Object.entries(process.env)
      .flatMap(([key, value]) => {
        return key.startsWith(prefix)
          ? [[key.substring(prefix.length), value]]
          : [];
      })
  );
}
