// The modules below register themselves on import, so the order of this file is their registration order.
// Modules migrated to a descriptor register later, when back.ts calls registerModules() (src/composition-root.ts):
// nothing imported here may read their registrations at import time.
// region registration attributes, need to be imported before any other modules
import './attributes/basicObject-registrationAttributes';
import './attributes/stixObject-registrationAttributes';
import './attributes/stixCoreObject-registrationAttributes';
import './attributes/stixDomainObject-registrationAttributes';
import './attributes/internalObject-registrationAttributes';
import './attributes/basicRelationship-registrationAttributes';
import './attributes/internalRelationship-registrationAttributes';
import './attributes/stixRelationship-registrationAttributes';
import './attributes/stixCoreRelationship-registrationAttributes';
import './attributes/stixRefRelationship-registrationAttributes';
import './attributes/stixSightingRelationship-registrationAttributes';
import './attributes/stixCyberObservable-registrationAttributes';
import './attributes/stixMetaObject-registrationAttributes';
// endregion
// region registration ref, need to be imported before any other modules
import './relationsRef/stixCoreObject-registrationRef';
import './relationsRef/stixDomainObject-registrationRef';
import './relationsRef/stixRelationship-registrationRef';
import './relationsRef/internalRelationship-registrationRef';
import './relationsRef/internalObject-registrationRef';
import './relationsRef/stixMetaObject-registrationRef';
import './relationsRef/stixCyberObservable-registrationRef';
// endregion
// region registration modules, need to be imported before graphql code registration
import './connector/connector';

// incomplete modules
// endregion
// region graphql registration
import './connector/connector-graphql';
import './ingestionHealth/ingestionHealth-graphql';
import './configPreset/configPreset-graphql';
// endregion
