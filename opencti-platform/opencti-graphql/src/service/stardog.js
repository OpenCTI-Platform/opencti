import conf from '../config/conf';
import pkg from 'stardog';
const { Connection, server } = pkg;

const endpoint = conf.get('stardog:endpoint');
const username = conf.get('stardog:username');
const password = conf.get('stardog:password');

const conn = new Connection({
  endpoint: endpoint,
  username: username,
  password: password
  } );

export const stardogAlive = async () => {
  try {
    await server.status( conn, { databases: false} );
    return true;
  } catch (e) {
      return false;
  }
};