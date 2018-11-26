import axios from 'axios';
import conf from '../config/conf';

const instance = axios.create({
  baseURL: conf.get('grakn:baseURL'),
  timeout: conf.get('grakn:timeout')
});

export const qk = queryDef =>
  instance({
    method: 'post',
    url: '/kb/grakn/graql',
    data: queryDef
  }).catch(() => {
    console.log('GRAKN QUERY ERROR', queryDef);
  });

export default instance;
