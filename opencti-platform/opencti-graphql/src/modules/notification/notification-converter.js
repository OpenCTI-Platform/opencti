import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import { buildStixObject, cleanObject } from '../../database/stix-converter';
// Outcomes
// Triggers
export const convertTriggerToStix = (instance) => {
    const stixObject = buildStixObject(instance);
    return Object.assign(Object.assign({}, stixObject), { name: instance.name, description: instance.description, extensions: {
            [STIX_EXT_OCTI]: cleanObject(Object.assign(Object.assign({}, stixObject.extensions[STIX_EXT_OCTI]), { extension_type: 'new-sdo' }))
        } });
};
// Notifications
export const convertNotificationToStix = (instance) => {
    const stixObject = buildStixObject(instance);
    return Object.assign(Object.assign({}, stixObject), { messages: instance.messages, is_read: instance.is_read, extensions: {
            [STIX_EXT_OCTI]: cleanObject(Object.assign(Object.assign({}, stixObject.extensions[STIX_EXT_OCTI]), { extension_type: 'new-sdo' }))
        } });
};
