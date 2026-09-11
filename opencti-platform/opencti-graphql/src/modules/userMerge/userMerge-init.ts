import { registerUserMergeHandlers } from './userMerge-handlers';

// The handlers derive part of their targets from the schema, so they can only be registered
// once every module has declared its attributes. Running it here rather than in the handler
// module keeps `registerUserMergeHandlers` callable on its own by the suites that reset the
// registry.
registerUserMergeHandlers();
