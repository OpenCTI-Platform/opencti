import { getGraknVersion } from '../database/grakn';
import { getElasticVersion } from '../database/elasticSearch';
import { getRedisVersion } from '../database/redis';
import { getRabbitMQVersion } from '../database/rabbitmq';
import { version } from '../../package.json';

const appVersion = async () => {
  return version;
};

const getInfo = async () => {
  return {
    app_version: await appVersion(),
    grakn_version: await getGraknVersion(),
    elasticsearch_version: await getElasticVersion(),
    rabbitmq_version: await getRabbitMQVersion(),
    redis_version: await getRedisVersion()
  };
};

export default getInfo;
