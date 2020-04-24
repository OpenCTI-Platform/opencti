import { findAll, logsWorkerConfig  } from '../domain/log';

const logResolvers = {
  Query: {
    logs: (_, args) => findAll(args),
    logsWorkerConfig: () => logsWorkerConfig()
  },
};

export default logResolvers;
