import type { ModuleDescriptor } from '../module-descriptor';
import { ENTITY_TYPE_EXTERNAL_REFERENCE } from '../../schema/stixMetaObject';
import { externalReferenceDefaultOverviewLayout } from './externalReference';

const externalReferenceModule: ModuleDescriptor = {
  id: 'externalReference',
  overviewLayouts: [{ entityType: ENTITY_TYPE_EXTERNAL_REFERENCE, layout: externalReferenceDefaultOverviewLayout }],
};

export default externalReferenceModule;
