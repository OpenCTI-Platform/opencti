import { v4 as uuidv4 } from 'uuid';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreEntityWorkspace } from './workspace-types';
import { FunctionalError } from '../../config/errors';
import { stixLoadByIds } from '../../database/middleware';
import { convertTypeToStixType } from '../../database/stix-converter';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../../schema/stixDomainObject';
import { STIX_SPEC_VERSION } from '../../database/stix';
import { generateStandardId } from '../../schema/identifier';
import type { StixId, StixObject } from '../../types/stix-common';
import { BasicStoreEntityGrouping } from '../grouping/grouping-types';
import { elList } from '../../database/middleware-loader';
import { READ_INDEX_INTERNAL_OBJECTS } from '../../database/utils';
import { addWorkspace } from './workspace-domain';
import type { BasicStoreEntity } from '../../types/store';

const EXPORTABLE_INVESTIGATED_TYPES: string[] = ['Stix-Core-Object', 'Stix-Core-Relationship', 'Stix-Sighting-Relationship'];

type StixReportForExport = {
  id: StixId;
  name: string;
  object_refs: StixId[];
  published: Date;
  spec_version: string;
  type: string
};

const buildStixReportForExport = (workspace: BasicStoreEntityWorkspace, stixInvestigatedEntities: StixObject[]): StixReportForExport => {
  const stixReportBundleWithoutId = {
    name: workspace.name,
    object_refs: stixInvestigatedEntities.map((s) => s.id),
    published: workspace.created_at,
    spec_version: STIX_SPEC_VERSION,
    type: convertTypeToStixType(ENTITY_TYPE_CONTAINER_REPORT),
  };
  const id = generateStandardId(ENTITY_TYPE_CONTAINER_REPORT, stixReportBundleWithoutId) as StixId;

  return { id, ...stixReportBundleWithoutId };
};

type StixBundle = {
  id: string;
  objects: (StixObject | StixReportForExport)[];
  type: string
};

const buildStixReportBundle = (stixObjects: (StixReportForExport | StixObject)[]): StixBundle => {
  return ({
    id: `bundle--${uuidv4()}`,
    objects: stixObjects,
    type: 'bundle'
  });
};

export const toStixReportBundle = async (context: AuthContext, user: AuthUser, workspace: BasicStoreEntityWorkspace): Promise<string> => {
  if (workspace.type !== 'investigation') {
    throw FunctionalError('You can only export investigation objects as a stix report bundle.');
  }

  const investigatedEntitiesIds = workspace.investigated_entities_ids ?? [];

  const stixInvestigatedEntities = await stixLoadByIds(context, user, investigatedEntitiesIds, { type: EXPORTABLE_INVESTIGATED_TYPES });
  const stixInvestigationAsReportForExport = buildStixReportForExport(workspace, stixInvestigatedEntities);
  const bundle = buildStixReportBundle([stixInvestigationAsReportForExport, ...stixInvestigatedEntities]);

  return JSON.stringify(bundle);
};

const nameInvestigationToStartFromContainer = async (context: AuthContext, user: AuthUser, container: BasicStoreEntity) => {
  const InvestigationToStartCanonicalName = `investigation from ${container.entity_type.toLowerCase()} "${container.name}"`;
  const investigations: any = await elList(context, user, [READ_INDEX_INTERNAL_OBJECTS], {
    filters: [{
      key: 'entity_type',
      values: ['workspace'],
    }, {
      key: 'type',
      values: ['investigation']
    }]
  });

  const investigationNameToMatch: RegExp = new RegExp(`^${InvestigationToStartCanonicalName} (\\d+)$`);
  const highestInvestigationNumber = investigations
    .map((investigation: { name: string; }) => {
      const matches = investigation.name.match(investigationNameToMatch);

      return matches ? Number(matches[1]) : 0;
    })
    .sort((a: number, b: number) => b - a)[0];

  if (highestInvestigationNumber === undefined) {
    return InvestigationToStartCanonicalName;
  } if (highestInvestigationNumber === 0) {
    return `${InvestigationToStartCanonicalName} 2`;
  }

  return `${InvestigationToStartCanonicalName} ${highestInvestigationNumber + 1}`;
};

export const startInvestigationFromContainer = async (context: AuthContext, user: AuthUser, container: BasicStoreEntity) => {
  const investigationInput = {
    type: 'investigation',
    name: await nameInvestigationToStartFromContainer(context, user, container),
    investigated_entities_ids: container.object
  };

  return addWorkspace(context, user, investigationInput);
};
