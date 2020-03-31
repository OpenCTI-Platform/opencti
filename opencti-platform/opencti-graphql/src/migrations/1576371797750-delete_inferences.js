import { executeWrite } from '../database/grakn';

export const up = async (next) => {
  const query = `match $r sub rule; get;`;
  await executeWrite(async (wTx) => {
    const iterator = await wTx.tx.query(query);
    const answers = await iterator.collect();
    return Promise.all(
      answers.map(async (answer) => {
        const rule = answer.map().get('r');
        const label = await rule.label();
        return wTx.tx.query(`undefine ${label} sub rule;`);
      })
    );
  });
  next();
};

export const down = async (next) => {
  next();
};
