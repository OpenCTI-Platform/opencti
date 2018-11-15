import Grakn from 'grakn';
import conf from '../config/conf';

const session = () => {
  const grakn = new Grakn(conf.get('grakn:uri'));
  return grakn.session('grakn');
};
const driver = session();
export default driver;
