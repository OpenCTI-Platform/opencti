import { describe, it, vi, expect } from 'vitest';
import * as engineMock from '../../src/database/engine';
import { checkSystemDependencies } from '../../src/boot-utils';
import * as fileStorageMock from '../../src/database/raw-file-storage';
import * as rabbitMqMock from '../../src/database/rabbitmq';
import * as redisMock from '../../src/database/redis';
import * as SMTPMock from '../../src/database/smtp';
import * as pythonMock from '../../src/python/pythonBridge';

describe('Initialization unit test', () => {
  it('should all dependencies be checked', async () => {
    // It's not only doing check but also init.
    // We don't want to init twice (see globalSetup.js) so Mocking them
    vi.spyOn(engineMock, 'searchEngineInit').mockResolvedValue(true);
    vi.spyOn(fileStorageMock, 'storageInit').mockResolvedValue(true);
    vi.spyOn(rabbitMqMock, 'rabbitMQIsAlive').mockResolvedValue(true);
    vi.spyOn(redisMock, 'redisInit').mockResolvedValue(true);
    vi.spyOn(SMTPMock, 'smtpIsAlive').mockResolvedValue(true);
    vi.spyOn(pythonMock, 'checkPythonAvailability').mockResolvedValue(true);
    const initResult = await checkSystemDependencies();
    expect(initResult).toBeTruthy();
  });

  it('should one dependency check throwing exception be rethrow', async () => {
    // It's not only doing check but also init.
    // We don't want to init twice (see globalSetup.js) so Mocking them
    vi.spyOn(engineMock, 'searchEngineInit').mockResolvedValue(true);
    vi.spyOn(fileStorageMock, 'storageInit').mockRejectedValue('Storage error for testing purpose');
    vi.spyOn(rabbitMqMock, 'rabbitMQIsAlive').mockResolvedValue(true);
    vi.spyOn(redisMock, 'redisInit').mockResolvedValue(true);
    vi.spyOn(SMTPMock, 'smtpIsAlive').mockResolvedValue(true);
    vi.spyOn(pythonMock, 'checkPythonAvailability').mockResolvedValue(true);
    await expect(checkSystemDependencies()).rejects.toThrow('Storage error for testing purpose');
  });
});
