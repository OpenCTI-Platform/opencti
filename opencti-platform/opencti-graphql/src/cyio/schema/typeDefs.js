import global from './global/typeDefs/index.js';
import assets from './assets/index.js' ;
import assessments from './assessments/index.js' ;

const typeDefs = [
    ...global,
    assets,
    assessments,
] ;

export default typeDefs ;