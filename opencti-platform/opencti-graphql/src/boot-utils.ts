// Check every dependency
import { logApp } from './config/conf';
import { searchEngineInit } from './database/engine';
import { storageInit } from './database/raw-file-storage';
import { redisInit } from './database/redis';
import { executionContext, SYSTEM_USER } from './utils/access';
import { checkPythonAvailability } from './python/pythonBridge';
import { smtpIsAlive } from './database/smtp';
import { rabbitMQIsAlive } from './database/rabbitmq';

export const checkSystemDependencies = async () => {
  logApp.info('[OPENCTI] Checking dependencies statuses');
  const context = executionContext('system_dependencies');
  const checkDependenciesPromises = [];
  checkDependenciesPromises.push(searchEngineInit());
  checkDependenciesPromises.push(storageInit());
  checkDependenciesPromises.push(rabbitMQIsAlive());
  checkDependenciesPromises.push(redisInit());
  checkDependenciesPromises.push(smtpIsAlive());
  checkDependenciesPromises.push(checkPythonAvailability(context, SYSTEM_USER));
  await Promise.all(checkDependenciesPromises);
  return true;
};
