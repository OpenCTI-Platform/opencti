import axios from 'axios';
import conf from '../config/conf';

const instance = axios.create({
  baseURL: conf.get('grakn:baseURL'),
  timeout: conf.get('grakn:timeout')
});

export default instance;
