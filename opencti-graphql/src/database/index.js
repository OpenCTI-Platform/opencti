import {v1} from 'neo4j-driver';

const uri = 'bolt://neo4j-community.opencti.io:7687';
const user = 'neo4j';
const password = 'opencti2018';

export const driver = v1.driver(uri, v1.auth.basic(user, password));