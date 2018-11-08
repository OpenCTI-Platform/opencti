/* eslint-disable no-console */
import { interval } from 'rxjs';
import { mergeMap, scan, take } from 'rxjs/operators';
import moment from 'moment';
import uuid from 'uuid/v5';
import { addMalware } from '../domain/malware';
import driver from './neo4j';

console.log('Starting data loader');

// Utils
const pad = (count, data) => {
  let s = String(data);
  while (s.length < (count.toString().length || 2)) {
    s = `0${s}`;
  }
  return s;
};
const randomString = () =>
  Math.random()
    .toString(36)
    .substring(7);

// Belts <white><yellow><orange><green><blue><brown><black><red>
// 01. Cleanup every elements
// apoc is a module to install on the graph
// call apoc.periodic.iterate("MATCH (n:Malware) return n", "DETACH DELETE n", {batchSize:5000}) yield batches, total return batches, total
// Todo

// 02. Create malwares
// Query info
// Considering the malwares created in step 02, with the access right <green>,<opencti> et <openex>
// -> <green> is translated to <white><yellow><orange><green> to respect the hierarchy.
// Considering a user with access <luatix> and <yellow>, the request to get the corresponding malwares is:
// PROFILE MATCH (m:Malware) WHERE m.access_rights contains '<luatix>' or m.access_rights contains '<yellow>' return m LIMIT 25
const malwareCount = 10000;
const writeMalware = malwareId =>
  addMalware({
    id: `malware--${malwareId}`,
    created: moment().toISOString(),
    labels: [randomString()],
    name: `malware-${malwareId}-${randomString()}`,
    description: `malware-${randomString()}`,
    access_rights: '<white><yellow><orange><green>,<opencti>,<openex>'
  });
const start = Date.now();
interval(1) // each 1 ms
  .pipe(take(malwareCount)) // Take only the number of creation we want
  .pipe(mergeMap(id => writeMalware(uuid(`malware--${id}`, uuid.URL)))) // mergeMap to wait for query completion
  .pipe(scan(acc => acc + 1, 0)) // Accumulate the number of execution
  .subscribe(
    counter => {
      process.stdout.write(
        `Creating malware: ${pad(malwareCount, counter)}/${malwareCount}\r`
      );
    },
    error => {
      driver.close();
      console.log(error);
    },
    () => {
      driver.close();
      const duration = Date.now() - start;
      // Compute average request time
      const avgInMs = (duration / malwareCount).toFixed(2);
      const seconds = Math.floor(duration / 1000);
      console.log(
        `\nIntegration done in ${seconds} sec (avg time per request: ${avgInMs} ms)`
      );
    }
  );

// 03. Create ?
// Todo
