import {PubSub} from 'graphql-subscriptions';

//This is only valid for development
//TODO move to redis implementation for production.
export const pubsub = new PubSub();