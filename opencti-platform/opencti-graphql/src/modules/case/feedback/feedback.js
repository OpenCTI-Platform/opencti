import { ENTITY_TYPE_CONTAINER_FEEDBACK } from './feedback-types';
import { ENTITY_TYPE_CONTAINER_CASE } from '../case-types';
import { NAME_FIELD, normalizeName } from '../../../schema/identifier';
import { registerDefinition } from '../../../schema/module';
import convertFeedbackToStix from './feedback-converter';
import { createdBy, objectAssignee, objectMarking } from '../../../schema/stixRefRelationship';
import { authorizedMembers } from '../../../schema/attribute-definition';
const FEEDBACK_DEFINITION = {
    type: {
        id: 'feedback',
        name: ENTITY_TYPE_CONTAINER_FEEDBACK,
        category: ENTITY_TYPE_CONTAINER_CASE,
        aliased: false
    },
    identifier: {
        definition: {
            [ENTITY_TYPE_CONTAINER_FEEDBACK]: [{ src: NAME_FIELD }, { src: 'created' }]
        },
        resolvers: {
            name(data) {
                return normalizeName(data);
            },
        },
    },
    attributes: [
        { name: 'rating', label: 'Rating', type: 'numeric', precision: 'integer', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
        authorizedMembers
    ],
    relations: [],
    relationsRefs: [
        Object.assign(Object.assign({}, createdBy), { mandatoryType: 'no', editDefault: false }),
        Object.assign(Object.assign({}, objectMarking), { mandatoryType: 'no', editDefault: false }),
        Object.assign(Object.assign({}, objectAssignee), { mandatoryType: 'no', editDefault: false }),
    ],
    representative: (stix) => {
        return stix.name;
    },
    converter: convertFeedbackToStix
};
registerDefinition(FEEDBACK_DEFINITION);
