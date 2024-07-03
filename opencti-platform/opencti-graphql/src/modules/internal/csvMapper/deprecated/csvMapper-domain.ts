// region [>=6.3 & <6.6]
import { Readable } from 'stream';
import type { AuthContext, AuthUser } from '../../../../types/user';
import { FunctionalError } from '../../../../config/errors';
import { parseCsvMapper } from '../csvMapper-utils';
import { parseReadableToLines } from '../../../../parser/csv-parser';
import { bundleProcess } from '../../../../parser/csv-bundler';

/**
 * @deprecated [>=6.3 & <6.6]. Use `csvMapperTest mutation`.
 */
export const csvMapperTest = async (context: AuthContext, user: AuthUser, configuration: string, content: string) => {
  let parsedConfiguration;
  try {
    parsedConfiguration = JSON.parse(configuration);
  } catch (error) {
    throw FunctionalError('Could not parse CSV mapper configuration', { error });
  }
  const csvMapper = parseCsvMapper(parsedConfiguration);
  const csvLines = await parseReadableToLines(Readable.from([content]), 100);
  const bundle = await bundleProcess(context, user, csvLines, csvMapper);
  return {
    objects: JSON.stringify(bundle.objects, null, 2),
    nbRelationships: bundle.objects.filter((object) => object.type === 'relationship').length,
    nbEntities: bundle.objects.filter((object) => object.type !== 'relationship').length,
  };
};
// endregion
