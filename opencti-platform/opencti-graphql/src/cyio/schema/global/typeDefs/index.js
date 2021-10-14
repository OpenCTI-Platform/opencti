import { Query, Mutation } from './entryPoints.js';
import directives from './directives.js';
import scalars from './scalars.js';
import common from './common.js';

const global = [
    Query, 
    Mutation,
    directives, 
    scalars, 
    common
];

export default global;
