import { PubSub } from 'graphql-subscriptions';

// This is only valid for development
// TODO move to redis implementation for production.
const pubsub = new PubSub();
export default pubsub;
