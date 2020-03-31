import { Promise } from 'bluebird';
import { findAll } from '../domain/tag';
import { executeWrite, updateAttribute } from '../database/grakn';

export const up = async (next) => {
  const alienTags = await findAll({ filters: [{ key: 'tag_type', values: ['AlienVault'] }] });
  if (alienTags && alienTags.edges) {
    await Promise.map(
      alienTags.edges,
      (tagEdge) => {
        const tag = tagEdge.node;
        return executeWrite((wTx) => {
          return updateAttribute(
            tag.id,
            'Tag',
            {
              key: 'color',
              value: ['#489044'],
            },
            wTx,
            { forceUpdate: true }
          );
        });
      },
      { concurrency: 3 }
    );
  }
  const vtTags = await findAll({ filters: [{ key: 'tag_type', values: ['VirusTotal'] }] });
  if (vtTags && vtTags.edges) {
    await Promise.map(
      vtTags.edges,
      (tagEdge) => {
        const tag = tagEdge.node;
        return executeWrite((wTx) => {
          return updateAttribute(
            tag.id,
            'Tag',
            {
              key: 'color',
              value: ['#0059f7'],
            },
            wTx,
            { forceUpdate: true }
          );
        });
      },
      { concurrency: 3 }
    );
  }
  next();
};

export const down = async (next) => {
  next();
};
