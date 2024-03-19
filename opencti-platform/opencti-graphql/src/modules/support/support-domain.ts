import fs from 'node:fs';
import { logApp } from '../../config/conf';
import type { AuthContext, AuthUser } from '../../types/user';
import { createInternalObject } from '../../domain/internalObject';
import { type BasicStoreEntitySupportPackage, ENTITY_TYPE_SUPPORT_PACKAGE, type StoreEntitySupportPackage } from './support-types';
import { storeLoadById } from '../../database/middleware-loader';

export const addSupportPackage = async (context: AuthContext, user: AuthUser, input: any) => {
  return createInternalObject<StoreEntitySupportPackage>(context, user, input, ENTITY_TYPE_SUPPORT_PACKAGE);
};

export const findById = (context: AuthContext, user: AuthUser, id: string) => {
  return storeLoadById<BasicStoreEntitySupportPackage>(context, user, id, ENTITY_TYPE_SUPPORT_PACKAGE);
};

export const findInLogs = () => {
  const options = {
    from: new Date('2024-03-19'),
    until: new Date(),
    limit: 10,
    start: 0,
    order: 'desc',
    fields: ['message'],
    format: 'json',
    json: true
  };

  const callback = (err: Error, results: any) => {
    console.log('Err', err);
    console.log('Results', results);
  };

  logApp.query(options, callback);
};

export const getLogFile = () => {
  console.log('Getting support logs');

  fs.readdir('.support', (err, files) => {
    files.forEach((file) => {
      console.log('File:', file);
    });
  });
};
