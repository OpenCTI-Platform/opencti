import {
  connectorDelete,
  connectors,
  connectorsForExport,
  connectorsForImport,
  pingConnector,
  registerConnector,
  resetStateConnector,
} from '../domain/connector';
import { computeWorkStatus, connectorForWork, deleteWork, initiateJob, jobsForWork, updateJob } from '../domain/work';

const connectorResolvers = {
  Query: {
    connectors: () => connectors(),
    connectorsForExport: () => connectorsForExport(),
    connectorsForImport: () => connectorsForImport(),
  },
  Work: {
    jobs: (work) => jobsForWork(work.id),
    status: (work) => computeWorkStatus(work.id),
    connector: (work) => connectorForWork(work.id),
  },
  Mutation: {
    deleteConnector: (_, { id }, { user }) => connectorDelete(user, id),
    registerConnector: (_, { input }, { user }) => registerConnector(user, input),
    resetStateConnector: (_, { id }, { user }) => resetStateConnector(user, id),
    pingConnector: (_, { id, state }, { user }) => pingConnector(user, id, state),
    initiateJob: (_, { workId }) => initiateJob(workId),
    updateJob: (_, { jobId, status, messages }) => updateJob(jobId, status, messages),
    deleteWork: (_, { id }) => deleteWork(id),
  },
};

export default connectorResolvers;
