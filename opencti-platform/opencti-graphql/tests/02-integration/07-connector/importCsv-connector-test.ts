/* eslint-disable max-len */
import { describe, it, expect } from 'vitest';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { processCSVforWorkers } from '../../../src/connector/importCsv/importCsv-connector';
import { csvMapperMockSimpleCities } from './importCsv-connector/csv-mapper-cities';
import { createWork, findById as findWorkById } from '../../../src/domain/work';
import { IMPORT_CSV_CONNECTOR } from '../../../src/connector/importCsv/importCsv';
import type { CsvMapperParsed } from '../../../src/modules/internal/csvMapper/csvMapper-types';
import { resolveUserByIdFromCache } from '../../../src/domain/user';
import type { AuthUser } from '../../../src/types/user';
import conf from '../../../src/config/conf';
import { IMPORT_STORAGE_PATH } from '../../../src/modules/internal/document/document-domain';
import { fileToReadStream, uploadToStorage } from '../../../src/database/file-storage';
import type { CsvBundlerIngestionOpts } from '../../../src/parser/csv-bundler';

describe('Verify internal importCsv connector', () => {
  let work: any;

  it('should import_csv_built_in_connector configuration be not changed on test', async () => {
    // Small bulk size to validate that there is no regression when there is more data than bulk size.
    expect(conf.get('import_csv_built_in_connector:bulk_creation_size'), 'Please be careful when changing bulk_creation_size in tests config').toBe(5);
  });

  it('should upload csv and create work that is use for this test', async () => {
    const file = fileToReadStream('./tests/02-integration/07-connector/importCsv-connector', 'csv-file-cities.csv', 'csv-file-cities.csv', 'text/csv');
    const uploadedFile = await uploadToStorage(testContext, ADMIN_USER, `${IMPORT_STORAGE_PATH}/global`, file, {});
    expect(uploadedFile).toBeDefined();
    expect(uploadedFile.upload.id).toBe('import/global/csv-file-cities.csv');

    work = await createWork(testContext, ADMIN_USER, IMPORT_CSV_CONNECTOR, '[File] Import csv for test', 'sourceTest');
  });

  it('should convert csv lines to bundle when line count < bulk_creation_size', async () => {
    const user = await resolveUserByIdFromCache(testContext, ADMIN_USER.id) as AuthUser;

    const mapperOpts: CsvBundlerIngestionOpts = {
      connectorId: 'test-connector',
      applicantUser: user,
      csvMapper: csvMapperMockSimpleCities as CsvMapperParsed,
      entity: undefined,
      workId: work.id
    };
    const { totalObjectsCount, totalBundlesCount } = await processCSVforWorkers(testContext, 'import/global/csv-file-cities.csv', mapperOpts);

    // Bulk size = 5
    //
    // 3 first city line (not 5 because of comment and header):
    //  25620,ville du pont,25650,ville du pont,46.999873398,6.498147193,doubs,25,bourgogne-franche-comté,Bourgogne-Franche-Comté,importcsv1,#ffffff => bundle #1, 2 objects (city+label)
    //  25620,ville du pont,25650,ville du pont,46.999873398,6.498147193,doubs,25,bourgogne-franche-comté,Bourgogne-Franche-Comté,importcsv2,#000000 => bundle #2 => 2 objects
    //  25624,villers grelot,25640,villers grelot,47.361512085,6.235167025,doubs,25,bourgogne-franche-comté,Bourgogne-Franche-Comté,importcsv1,#ffffff => bundle #2 => 2 objects
    // => 2 bundles and 6 objects
    //
    // next 5 lines:
    // 25615,villars les blamont,25310,villars les blamont,47.368383721,6.871414913,doubs,25,bourgogne-franche-comté,Bourgogne-Franche-Comté,importcsv1,#ffffff => bundle #1, 2 objects
    // 25619,les villedieu,25240,les villedieu,46.713906258,6.26583065,doubs,25,bourgogne-franche-comté,Bourgogne-Franche-Comté,importcsv1,#ffffff => bundle #1, 2 object
    // 25622,villers buzon,25170,villers buzon,47.228558434,5.852186748,doubs,25,bourgogne-franche-comté,Bourgogne-Franche-Comté,importcsv1,#ffffff => bundle #1, 2 object
    // #25666,skip city,25666,skip city,47.240809828,6.473842387,skip-dept,25,skip-region,skip-region,importcsv1,#ffffff => comment = skip
    // 25625,villers la combe,25510,villers la combe,47.240809828,6.473842387,doubs,25,bourgogne-franche-comté,Bourgogne-Franche-Comté,importcsv1,#ffffff => bundle #1, 2 object
    // => 1 bundles and 5 objects
    //
    // next 5 lines:
    // 25627,villers sous chalamont,25270,villers sous chalamont,46.901588322,6.045328224,doubs,25,bourgogne-franche-comté,Bourgogne-Franche-Comté,importcsv1,#ffffff => bundle #1, 2 objects
    // 25632,voujeaucourt,25420,voujeaucourt,47.473552905,6.782505604,doubs,25,bourgogne-franche-comté,Bourgogne-Franche-Comté,importcsv1,#ffffff => bundle #1, 1 object
    // 02102,bouconville vauclair,02860,bouconville vauclair,49.460193485,3.756684634,aisne,02,hauts-de-france,Hauts-de-France,importcsv1,#ffffff => bundle #1, 1 object
    // 02105,bouresches,02400,bouresches,49.067056293,3.316703204,aisne,02,hauts-de-france,Hauts-de-France,importcsv1,#ffffff => bundle #1, 1 object
    // 02124,brissy hamegicourt,02240,brissy hamegicourt,49.742857871,3.399923608,aisne,02,hauts-de-france,Hauts-de-France,importcsv1,#ffffff => bundle #1, 1 object
    // => 1 bundles and 6 objects
    //
    // next 5 lines:
    // 02125,brumetz,02810,brumetz,49.110351585,3.153350725,aisne,02,hauts-de-france,Hauts-de-France,importcsv1,#ffffff => bundle #1, 2 objects
    // 02126,brunehamel,02360,brunehamel,49.771382057,4.186261479,aisne,02,hauts-de-france,Hauts-de-France,importcsv1,#ffffff => bundle #1, 1 object
    // 02131,bucy le long,02880,bucy le long,49.387973822,3.398519722,aisne,02,hauts-de-france,Hauts-de-France,importcsv1,#ffffff => bundle #1, 1 object
    // 02131,bucy le long,02880,bucy le long,49.387973822,3.398519722,aisne,02,hauts-de-france,Hauts-de-France,importcsv3,#000000 => bundle #2, 2 object (new bundle because same city with different label)
    // => 2 bundles and 6 objects
    //
    expect(totalBundlesCount).toBe(6);
    expect(totalObjectsCount).toBe(23);

    const workUpdated: any = await findWorkById(testContext, ADMIN_USER, work.id);
    expect(workUpdated).toBeDefined();
    expect(workUpdated.errors.length).toBe(0);

    // As connector is not a real one, there is no messages in queue
    // If we want to validate the data, a new connector registration will be needed
  });
});
