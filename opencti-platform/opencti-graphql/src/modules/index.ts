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
import './channel/channel';
import './connector/connector';
import './language/language';
import './event/event';
import './grouping/grouping';
import './narrative/narrative';
import './notification/notification';
import './dataComponent/dataComponent';
import './dataSource/dataSource';
import './vocabulary/vocabulary';
import './administrativeArea/administrativeArea';
import './task/task';
import './task/task-template/task-template';
import './case/case';

// incomplete modules
// endregion
// region graphql registration
import './channel/channel-graphql';
import './connector/connector-graphql';
import './ingestionHealth/ingestionHealth-graphql';
import './catalog/catalog-graphql';
import './language/language-graphql';
import './event/event-graphql';
import './grouping/grouping-graphql';
import './narrative/narrative-graphql';
import './notification/notification-graphql';
import './dataComponent/dataComponent-graphql';
import './dataSource/dataSource-graphql';
import './vocabulary/vocabulary-graphql';
import './administrativeArea/administrativeArea-graphql';
import './task/task-graphql';
import './task/task-template/task-template-graphql';
import './case/case-graphql';
import './configPreset/configPreset-graphql';
// endregion
