/*
 * Filename: _DISABLED-eo14168-vocabularies.js
 *
 * This migration is disabled by default. System Owners only need to run the migration if you are implementing the
 * application of the USG_EO_14168_COMPLIANT feature flag. This feature flag applies platform compliance to the
 * US Government Executive Order 14168 which mandates that US Government Agencies use "sex" instead of "gender"
 * within deployed applications/forms/policies/etc. It additionally specifies vocabularies that can be used
 * to define "sex".
 *
 * To enable the feature flag, add USG_EO_14168_COMPLIANT to the opencti-graphql/conf/default.json
 * (or whichever config you use to launch your platform)
 * Example:
 * app: {
 * ....... some config file options ......
 *        "enabled_dev_features": [
 *              "USG_EO_14168_COMPLIANT"
 *          ],
 * ....... more config file options ......
 * }
 *
 * You will then need to rename this migration file by replacing _DISABLED with the current milliseconds from epoch.
 *
 * Example: _DISABLED-eo14168-vocabularies.js --> 1749044611722-eo14168-vocabularies.js
 *  Where the 1749044611722 in standard GMT time translates to: Wednesday, June 4, 2025 1:43:31.722 PM
 *
 * To get the current milliseconds from epoch for use in the rename here are various methods:
 *    - Date command rounded to nearest millisecond: date +%s000
 *    - Python command: python3 -c 'import time; print(int(time.time() * 1000))'
 *    - Node command: node -e 'console.log(Date.now())'
 *
 * After you have done the above two steps (enabled the feature flag and renamed the file to a current epoch), you will
 * have to redeploy/build using the code repo you have made these changes within. At launch the OpenCTI instance it
 * will process the changes to the vocabularies stored within Elastic. Specifically, it will deleted the default
 * options of 'nonbinary' and 'other'. It will add a new option of 'unknown'.
 *
 * Records stored with the previous selection of 'nonbinary' or 'other' will move to 'null'.
 * They are not migrated to the new 'other' selection, by default, however the migration could support this, if added.
 * Lastly, the "Gender" UI field will now reflect 'Sex' as the field name on forms and in
 * change history actions.
 */

import { logMigration } from '../config/conf';
import { elRawSearch } from '../database/engine';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { addVocabulary, deleteVocabulary } from '../modules/vocabulary/vocabulary-domain';
import { READ_INDEX_STIX_META_OBJECTS } from '../database/utils';

const newVocabularies = {
  gender_ov: [
    // { key: 'male' }, // Gender and Sex Option  - USG EO 14168 Compliant - remains/existing
    // { key: 'female' }, // Gender and Sex Option  - USG EO 14168 Compliant - remains/existing
    { key: 'unknown' }, // Sex option - USG EO 14168 Compliant - to be added by migration
    // { key: 'nonbinary' }, // Gender option - NOT USG EO 14168 Compliant - to be removed by migration
    // { key: 'other' }, // Gender option - NOT USG EO 14168 Compliant - to be removed by migration
  ],
};

const deleteVocabularies = [
  'nonbinary', // Gender option - NOT USG EO 14168 Compliant - to be removed by migration
  'other', // Gender option - NOT USG EO 14168 Compliant - to be removed by migration
];

const message = '[MIGRATION] EO 14168 Migration';
export const up = async (next) => {
  logMigration.info(`${message} > started`);
  // Create new vocabularies
  const context = executionContext('migration');
  const vocabularyKeys = Object.keys(newVocabularies);
  for (let i = 0; i < vocabularyKeys.length; i += 1) {
    const key = vocabularyKeys[i];
    const elements = newVocabularies[key];
    for (let elementIndex = 0; elementIndex < elements.length; elementIndex += 1) {
      const element = elements[elementIndex];
      const data = { name: element.key, description: '', category: key, builtIn: false };
      await addVocabulary(context, SYSTEM_USER, data);
    }
  }

  const query = {
    index: READ_INDEX_STIX_META_OBJECTS,
    body: {
      query: {
        term: {
          'category.keyword': {
            value: 'gender_ov',
          }
        }
      },
      size: 10
    },
  };
  const genderOVData = await elRawSearch(context, SYSTEM_USER, '', query);
  const genderOVHits = genderOVData.hits?.hits;
  logMigration.info(`${message} > finding vocabs to delete`);
  for (let index = 0; index < genderOVHits?.length; index += 1) {
    const currentEntityOV = genderOVHits[index];
    const currentEntityOVId = currentEntityOV._source.internal_id;
    const currentEntityOVName = currentEntityOV._source.name;
    if (deleteVocabularies.includes(currentEntityOVName)) {
      await deleteVocabulary(context, SYSTEM_USER, currentEntityOVId);
    }
  }
  logMigration.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
