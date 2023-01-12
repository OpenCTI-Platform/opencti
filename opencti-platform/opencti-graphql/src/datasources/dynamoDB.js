import { DataSource } from 'apollo-datasource';
import { InMemoryLRUCache } from 'apollo-server-caching';
import conf from '../config/conf';
import { 
  DynamoDBClient, 
  QueryCommand, 
  ScanCommand,
  PutItemCommand,
  DeleteItemCommand,
  UpdateItemCommand,
} from '@aws-sdk/client-dynamodb';


export default class DynamoDB extends DataSource {
  constructor( ) {
    super();

    const region = conf.get('dynamodb:region');
    const accessKeyId = conf.get('dynamodb:accessKeyId');
    const secretAccessKey = conf.get('dynamodb:secretAccessKey');
    const config = {
      "region": conf.get('dynamodb:region'),
      "credentials": {
        "accessKeyId": conf.get('dynamodb:accessKeyId'),
        "secretAccessKey": conf.get('dynamodb:secretAccessKey'),  
      }
    };

    this.client = new DynamoDBClient(config);
  }

  //
  // This is a function that gets called by ApolloServer when being setup.
  // This function gets called with the datasource config including things
  // like caches and context.  Assign this.context to the request context
  // here, so we can know about the user making requests
  //
  initialize( config ) {
    this.context = config.context ;
    this.cache = config.cache || new InMemoryLRUCache()
  }

  async queryByKey( {params, queryId = "'not-specified'"} ) {
    let data;
    try {
      data = await this.client.send( new QueryCommand(params) );
    } catch(err) {
        console.error(err);
        throw err;
    }
    return data;
  }

  // 
  // Queries the specified table using a scan and matching the provider criterial
  // matches is an array of match node each of which is defined as follows:
  //   {
  //     name: name,
  //     value: value,
  //     comparator:  = | < | <= | > | >=,
  //     expression: AND | OR | NOT | BETWEEN | IN
  //   }
  async queryByScan( {params, limit, queryId = "'not-specified'"}) {
    let data;
    try {
      data = await this.client.send( new ScanCommand(params) );
    } catch(err) {
        console.error(err);
        throw err;
    }
    return data;
  }

  async create( {params}) {
    let data;
    try {
      data = await this.client.send( new PutItemCommand(params) );
    } catch(err) {
        console.error(err);
        throw err;
    }
    return data;
  }

  async delete( {params}) {
    let data;
    try {
      data = await this.client.send( new DeleteItemCommand(params) );
    } catch(err) {
        console.error(err);
        throw err;
    }
    return data;

  }

  async edit( {params }) {
    let data;
    try {
      data = await this.client.send( new UpdateItemCommand(params) );
    } catch(err) {
        console.error(err);
        throw err;
    }
    return data;
  }
}


