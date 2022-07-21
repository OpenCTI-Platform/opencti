import { DataSource } from 'apollo-datasource';
import { InMemoryLRUCache } from 'apollo-server-caching';
import fetch from 'node-fetch';
import conf from '../config/conf.js';


export default class Artemis extends DataSource {
	constructor( ) {
		super()

		const host = conf.get('artemis:rest:hostname');
		const port = conf.get('artemis:rest:port');
		const username = conf.get('artemis:rest:username');
		const password = conf.get('artemisreset:passcode');
	
		this.credentials = Buffer.from(username + ":" + password).toString('base64');
		this.server_url = `https://${host}:${port}/rest/`;
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

  async publish(taskId, destination, payload ) {
	let msgCreateUrl;
	let url = this.server_url + destination;
	let topicResponse = await fetch(url, {
		method: 'get',
		headers: {
			'Authorization': 'Basic ' + this.credentials
		},
	});
	if (!topicResponse.ok) throw new HTTPResponseError(topicResponse);

	// get the msg-create URL from the header so that the post can be performed
	msgCreateUrl = topicResponse.headers.get('msg-create');

	// post the actual tasking
	let response = await fetch(msgCreateUrl, {
		method: 'post',
		headers: {
			'Authorization': 'Basic ' + this.credentials,
			'Content-Type': 'application/json'
		},
		body: JSON.stringify(payload)
	});
	if (!response.ok) throw new HTTPResponseError(topicResponse);

	// return the taskId if successful
	return taskId;
  }
}
