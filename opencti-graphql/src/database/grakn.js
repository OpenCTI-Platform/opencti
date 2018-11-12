import Grakn from 'grakn';
import conf from '../config/conf';

const driver = new Grakn(conf.get('grakn:uri'))

export default driver;
