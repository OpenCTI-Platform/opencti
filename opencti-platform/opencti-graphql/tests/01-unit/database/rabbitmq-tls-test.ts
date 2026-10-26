import { describe, expect, it, vi } from 'vitest';

// Return the options instead of a client, so the management client options can be asserted directly
vi.mock('../../../src/utils/http-client', () => ({
  getHttpClient: vi.fn((options: unknown) => options),
}));

vi.mock('amqplib/callback_api', () => ({
  default: {
    connect: vi.fn(),
    credentials: { plain: vi.fn() },
  },
}));

vi.mock('../../../src/config/tracing', () => ({
  telemetry: vi.fn(),
}));

vi.mock('../../../src/domain/work', () => ({
  updateExpectationsNumber: vi.fn(),
}));

// RabbitMQ TLS options are read once, when the module is loaded:
// reload it with the given global TLS default and rabbitmq configuration.
const loadRabbitmq = async (tlsRejectUnauthorized: boolean, rabbitmqConfig: Record<string, boolean> = {}) => {
  vi.resetModules();
  vi.doMock('../../../src/config/conf', async (importOriginal) => {
    const actual = await importOriginal<typeof import('../../../src/config/conf')>();
    const config: Record<string, boolean> = { 'rabbitmq:use_ssl': true, 'rabbitmq:management_ssl': true, ...rabbitmqConfig };
    return {
      ...actual,
      TLS_REJECT_UNAUTHORIZED: tlsRejectUnauthorized,
      booleanConf: (key: string, defaultValue: boolean) => (key in config ? config[key] : defaultValue),
      configureCA: () => ({}),
    };
  });
  return import('../../../src/database/rabbitmq');
};

describe('rabbitmq TLS certificate verification', () => {
  it('should verify certificates by default', async () => {
    const { rabbitmqConnectionOptions, rabbitmqManagementClient } = await loadRabbitmq(true);

    expect(rabbitmqConnectionOptions()).toMatchObject({ rejectUnauthorized: true });
    expect(await rabbitmqManagementClient()).toMatchObject({ rejectUnauthorized: true });
  });

  it('should follow the global TLS option when no rabbitmq option is set', async () => {
    const { rabbitmqConnectionOptions, rabbitmqManagementClient } = await loadRabbitmq(false);

    expect(rabbitmqConnectionOptions()).toMatchObject({ rejectUnauthorized: false });
    expect(await rabbitmqManagementClient()).toMatchObject({ rejectUnauthorized: false });
  });

  it('should let rabbitmq options override the global TLS option', async () => {
    const { rabbitmqConnectionOptions, rabbitmqManagementClient } = await loadRabbitmq(true, {
      'rabbitmq:use_ssl_reject_unauthorized': false,
      'rabbitmq:management_ssl_reject_unauthorized': false,
    });

    expect(rabbitmqConnectionOptions()).toMatchObject({ rejectUnauthorized: false });
    expect(await rabbitmqManagementClient()).toMatchObject({ rejectUnauthorized: false });
  });
});
