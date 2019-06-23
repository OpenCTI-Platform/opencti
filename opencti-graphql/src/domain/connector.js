import { readdirSync, readFileSync, lstatSync } from 'fs';
import { join } from 'path';
import uuid from 'uuid/v4';
import { isNil } from 'ramda';
import {
  commitWriteTx,
  queryOne,
  takeWriteTx,
  updateAttribute
} from '../database/grakn';
import conf, { logger } from '../config/conf';

export const getConnectors = async () => {
  const path = conf.get('app:connectors');
  const isDirectory = source => lstatSync(source).isDirectory();
  const getDirectories = source =>
    readdirSync(source)
      .map(name => join(source, name))
      .filter(isDirectory)
      .map(dir => dir.replace(`${path}/`, ''));
  return getDirectories(path).map(async connector => {
    const connectorConfigTemplate = readFileSync(
      `${path}/${connector}/config.json`
    );
    const connectorObject = await queryOne(
      `match $x isa Connector; $x has connector_identifier "${connector}"; get $x;`,
      ['x']
    );
    return {
      identifier: connector,
      config_template: Buffer.from(connectorConfigTemplate).toString('base64'),
      config: connectorObject ? connectorObject.x.connector_config : null
    };
  });
};

export const updateConfig = async (identifier, config) => {
  const connector = await queryOne(
    `match $x isa Connector; $x has connector_identifier "${identifier}"; get $x;`,
    ['x']
  );
  if (isNil(connector)) {
    const wTx = await takeWriteTx();
    const query = `insert $connector isa Connector,
    has internal_id "${uuid()}",
    has connector_identifier "${identifier}",
    has connector_config "${config}";`;
    logger.debug(`[GRAKN - infer: false] ${query}`);
    await wTx.tx.query(query);
    await commitWriteTx(wTx);
  } else {
    const { id } = connector.x;
    await updateAttribute(id, { key: 'connector_config', value: [config] });
  }
};
