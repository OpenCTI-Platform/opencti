import nconf from 'nconf';

let DEFAULT_ENV = 'development';

// Environment from NODE_ENV environment variable
nconf.add('env', {
    'whitelist': ['NODE_ENV']
});

// Environment from "-e" command line parameter
nconf.add('argv', {
    'e': {
        'alias': 'env',
        'describe': 'Execution environment'
    }
});

// Priority to command line parameter and fallback to DEFAULT_ENV
let environment = nconf.get('env') || nconf.get('NODE_ENV') || DEFAULT_ENV;
nconf.file(environment, './config/' + environment.toLowerCase() + '.json');
nconf.file('default', './config/default.json');

export default nconf;