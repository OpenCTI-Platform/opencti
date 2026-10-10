import { executionContext, SYSTEM_USER } from '../utils/access';
import { logMigration } from '../config/conf';
import { VocabularyCategory } from '../generated/graphql';
import { builtInOv } from '../modules/vocabulary/vocabulary-utils';
import { addVocabulary } from '../modules/vocabulary/vocabulary-domain';

const message = '[MIGRATION] migration title';

export const up = async (next: (error?: Error) => void) => {
  const startTime = Date.now();
  logMigration.info(`${message} > started`);
  // do your migration
  // see src/migration/README.md for best practices
  // if there is a loop, add a logMigration.info to display expected number and progress (ex: "processing 2/100 Indicators")
  const context = executionContext('migration');
  const category = VocabularyCategory.CitizenshipDocumentTypeOv;

  const data = [
    {
      name: 'birth-certificate',
      description: 'A Birth Certificate shows that a person was born within a country or to citizens of that country.',
      category,
      builtIn: builtInOv.includes(category),
    },
    {
      name: 'certificate-of-citizenship',
      description: 'Certificate of Citizenship is issued to people who obtain citizenship through parents or other legal processes.',
      category,
      builtIn: builtInOv.includes(category),
    },
    {
      name: 'certificate-of-naturalization',
      description: 'Certificate of Naturalization is Given to individuals who become citizens through the naturalization process.',
      category,
      builtIn: builtInOv.includes(category),
    },
    {
      name: 'national-Identity',
      description: 'A national Identity (ID) is an official government-issued identification document (or number) used to verify a person\'s identity within their home country.',
      category,
      builtIn: builtInOv.includes(category),
    },
    {
      name: 'passport',
      description: 'Although primarily a travel document, it is also strong evidence of citizenship.',
      category,
      builtIn: builtInOv.includes(category),
    },
  ];

  const promises = data.map(async (d) => {
    await addVocabulary(context, SYSTEM_USER, d);
  });

  // 2. Wait for all promises in the array to resolve
  await Promise.all(promises);

  logMigration.info(`${message} > done in ${Date.now() - startTime} ms`);
  next();
};

export const down = async (next: (error?: Error) => void) => {
  next();
};
