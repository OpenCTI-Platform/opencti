import { head } from 'ramda';
import {
  dayFormat,
  escape,
  escapeString,
  executeRead,
  executeWrite,
  extractQueryVars,
  getGraknVersion,
  graknIsAlive,
  load,
  monthFormat,
  now,
  prepareDate,
  sinceNowInMinutes,
  utcDate,
  yearFormat
} from '../../../src/database/grakn';

describe('Grakn basic and utils', () => {
  it('should database accessible', () => {
    expect(graknIsAlive()).toBeTruthy();
    expect(getGraknVersion()).toEqual('1.6.2');
  });
  it('should escape according to grakn needs', () => {
    expect(escape({ key: 'json' })).toEqual({ key: 'json' });
    expect(escape('simple ident')).toEqual('simple ident');
    expect(escape('grakn\\special')).toEqual('grakn\\\\special');
    expect(escape('grakn;injection')).toEqual('grakn\\;injection');
    expect(escape('grakn,injection')).toEqual('grakn\\,injection');
    expect(escapeString('"\\test\\"')).toEqual('\\"\\\\test\\\\\\"');
  });
  it('should date utils correct', () => {
    expect(utcDate().isValid()).toBeTruthy();
    expect(utcDate(now()).isValid()).toBeTruthy();
    expect(sinceNowInMinutes(now())).toEqual(0);
    // Test with specific timezone
    expect(prepareDate('2020-01-01T00:00:00.001+01:00')).toEqual('2019-12-31T23:00:00.001');
    expect(yearFormat('2020-01-01T00:00:00.001+01:00')).toEqual('2019');
    expect(monthFormat('2020-01-01T00:00:00.001+01:00')).toEqual('2019-12');
    expect(dayFormat('2020-01-01T00:00:00.001+01:00')).toEqual('2019-12-31');
    // Test with direct utc
    expect(prepareDate('2020-02-27T08:45:39.351Z')).toEqual('2020-02-27T08:45:39.351');
    expect(yearFormat('2020-02-27T08:45:39.351Z')).toEqual('2020');
    expect(monthFormat('2020-02-27T08:45:39.351Z')).toEqual('2020-02');
    expect(dayFormat('2020-02-27T08:45:39.351Z')).toEqual('2020-02-27');
  });
});

describe('Grakn low level commands', () => {
  it('should read transaction handle correctly', async () => {
    const data = await executeRead(rTx => {
      return rTx.tx.query(`match $x sub report_class; get;`).then(it => it.collect());
    });
    expect(data).not.toBeNull();
    expect(data.length).toEqual(1);
    const value = head(data).get('x');
    expect(value).not.toBeNull();
    expect(value.baseType).toEqual('ATTRIBUTE_TYPE');
  });
  it('should read transaction fail with bad query', async () => {
    const queryPromise = executeRead(rTx => {
      return rTx.tx.query(`match $x isa BAD_TYPE; get;`);
    });
    // noinspection ES6MissingAwait
    expect(queryPromise).rejects.toThrow();
  });
  it('should write transaction handle correctly', async () => {
    const connectorId = 'test-instance-connector';
    // Create a connector
    const creationData = await executeWrite(wTx => {
      return wTx.tx
        .query(`insert $c isa Connector, has internal_id_key "${connectorId}";`) //
        .then(it => it.collect());
    });
    expect(creationData).not.toBeNull();
    expect(creationData.length).toEqual(1);
    const value = head(creationData).get('c');
    expect(value).not.toBeNull();
    expect(value.id).not.toBeNull();
    expect(value.baseType).toEqual('ENTITY');
    // Delete it
    const deleteData = await executeWrite(wTx => {
      return wTx.tx
        .query(`match $c isa Connector, has internal_id_key "${connectorId}"; delete $c;`) //
        .then(it => it.collect());
    });
    expect(deleteData).not.toBeNull();
    expect(deleteData.length).toEqual(1);
    expect(head(deleteData).message()).toEqual('Delete successful.');
  });
  it('should write transaction fail with bad query', async () => {
    const queryPromise = executeRead(rTx => {
      return rTx.tx.query(`insert $c isa Connector, has invalid_attr "invalid";`);
    });
    // noinspection ES6MissingAwait
    expect(queryPromise).rejects.toThrow();
  });
  it('should query vars fully extracted', async () => {
    let vars = extractQueryVars('match $x sub report_class; get;');
    expect(vars).not.toBeNull();
    expect(vars.length).toEqual(1);
    expect(head(vars).alias).toEqual('x');
    expect(head(vars).role).toBeUndefined();
    expect(head(vars).internalIdKey).toBeUndefined();
    // Extract vars with relation roles
    vars = extractQueryVars('match $to isa Sector; $rel(part_of:$from, gather:$to) isa gathering; get;');
    expect(vars).not.toBeNull();
    expect(vars.length).toEqual(3);
    let aggregationMap = new Map(vars.map(i => [i.alias, i]));
    expect(aggregationMap.get('to').role).toEqual('gather');
    expect(aggregationMap.get('from').role).toEqual('part_of');
    // Extract var with internal_id specified
    vars = extractQueryVars(
      'match $to isa Sector; $rel(part_of:$from, gather:$to) isa gathering; $from has internal_id_key "ID"; get;'
    );
    expect(vars).not.toBeNull();
    expect(vars.length).toEqual(3);
    aggregationMap = new Map(vars.map(i => [i.alias, i]));
    expect(aggregationMap.get('from').internalIdKey).toEqual('ID');
    // Extract right role reconstruct
    vars = extractQueryVars('match $to isa Sector; ($from, gather:$to) isa gathering; get;');
    expect(vars).not.toBeNull();
    expect(vars.length).toEqual(2);
    aggregationMap = new Map(vars.map(i => [i.alias, i]));
    expect(aggregationMap.get('from').role).toEqual('part_of');
    expect(aggregationMap.get('to').role).toEqual('gather');
    // Extract left role reconstruct
    vars = extractQueryVars('match $to isa Sector; (part_of:$from, $to) isa gathering; get;');
    expect(vars.length).toEqual(2);
    aggregationMap = new Map(vars.map(i => [i.alias, i]));
    expect(aggregationMap.get('from').role).toEqual('part_of');
    expect(aggregationMap.get('to').role).toEqual('gather');
  });
});

describe('Grakn basic loader', () => {
  it('should load simple query', async () => {
    const query = 'match $m isa Malware; $m has stix_id_key "malware--c6006dd5-31ca-45c2-8ae0-4e428e712f88"; get;';
    const malware = await load(query, ['m'], { noCache: true });
    expect(malware.m).not.toBeNull();
    expect(malware.m.stix_id_key).toEqual('malware--c6006dd5-31ca-45c2-8ae0-4e428e712f88');
  });
});
