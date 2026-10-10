// Attributes and refs of the abstract types, registered on import. Every module definition inherits from them:
// this file is imported before registerModules() registers the modules (src/composition-root.ts).
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
