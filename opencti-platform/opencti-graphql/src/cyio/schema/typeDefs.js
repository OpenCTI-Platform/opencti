import global from './global/typeDefs/index';
import assets from './assets/index';
import assessments from './assessments/index';

const typeDefs = [...global, assets, assessments];

export default typeDefs;
