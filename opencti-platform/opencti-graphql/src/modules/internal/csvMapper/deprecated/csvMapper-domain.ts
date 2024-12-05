// region [>=6.3 & <6.6]
import { Readable } from 'stream';
import type { AuthContext, AuthUser } from '../../../../types/user';
import { FunctionalError } from '../../../../config/errors';
import { parseCsvMapper } from '../csvMapper-utils';
import { parseReadableToLines } from '../../../../parser/csv-parser';
import { type CsvBundlerTestOpts, getCsvTestObjects } from '../../../../parser/csv-bundler';

/**
 * @deprecated [>=6.4 & <6.7]. Use `csvMapperTest mutation`.
 */
export const csvMapperTest = async (context: AuthContext, user: AuthUser, configuration: string, content: string) => {
  let parsedConfiguration;
  try {
    parsedConfiguration = JSON.parse(configuration);
  } catch (error) {
    throw FunctionalError('Could not parse CSV mapper configuration', { error });
  }
  const csvMapperParsed = parseCsvMapper(parsedConfiguration);
  const csvLines = await parseReadableToLines(Readable.from([content]), 100);

  const bundlerOpts : CsvBundlerTestOpts = {
    applicantUser: user,
    csvMapper: csvMapperParsed
  };
  const allObjects = await getCsvTestObjects(context, csvLines, bundlerOpts);

  return {
    objects: JSON.stringify(allObjects, null, 2),
    nbRelationships: allObjects.filter((object) => object.type === 'relationship').length,
    nbEntities: allObjects.filter((object) => object.type !== 'relationship').length,
  };
};
// endregion
