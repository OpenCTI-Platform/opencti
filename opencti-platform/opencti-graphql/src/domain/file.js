import { map } from 'ramda';
import { loadFile, upload } from '../database/minio';
import { pushToConnector } from '../database/rabbitmq';
import { connectorsForImport } from './connector';
import { createWork } from './work';
import { logger } from '../config/conf';

const uploadJobImport = async (fileId, fileMime, context = null, token = null) => {
  const connectors = await connectorsForImport(fileMime, true);
  if (connectors.length > 0) {
    // Create job and send ask to broker
    const workList = await Promise.all(
      map(
        (connector) =>
          createWork(connector, null, null, context, fileId).then(({ work, job }) => ({
            connector,
            work,
            job,
          })),
        connectors
      )
    );
    // Send message to all correct connectors queues
    await Promise.all(
      map((data) => {
        const { connector, work, job } = data;
        const message = {
          work_id: work.internal_id_key, // work(id)
          work_context: context,
          job_id: job.internal_id_key, // job(id)
          token,
          file_mime: fileMime, // Ex. application/json
          file_path: `/storage/get/${fileId}`, // Path to get the file
          update: true,
        };
        return pushToConnector(connector, message);
      }, workList)
    );
  }
};

export const askJobImport = async (user, filename, context) => {
  logger.debug(`Job > ask import for file ${filename} by ${user.user_email}`);
  const file = await loadFile(filename);
  await uploadJobImport(file.id, file.metaData.mimetype, context, user.token.uuid);
  return file;
};
export const uploadImport = async (user, file) => {
  const up = await upload(user, 'import', file);
  await uploadJobImport(up.id, up.metaData.mimetype, user.token.uuid);
  return up;
};
