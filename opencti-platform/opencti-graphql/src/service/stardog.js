import pkg from 'stardog';
import conf from '../config/conf';

const { Connection, server } = pkg;

const endpoint = conf.get('stardog:endpoint');
const username = conf.get('stardog:username');
const password = conf.get('stardog:password');

const conn = new Connection({
  endpoint,
  username,
  password,
});

export const stardogAlive = async () => {
  try {
    await server.status(conn, { databases: false });
    return true;
  } catch (e) {
    return false;
  }
};
