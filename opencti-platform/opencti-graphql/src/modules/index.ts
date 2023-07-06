// region static registration attributes, need to be imported before any other modules
import './attributes/basicObject-registrationAttributes';
import './attributes/stixObject-registrationAttributes';
import './attributes/stixCoreObject-registrationAttributes';
import './attributes/stixDomainObject-registrationAttributes';
import './attributes/internalObject-registrationAttributes';
import './attributes/basicRelationship-registrationAttributes';
import './attributes/internalRelationship-registrationAttributes';
import './attributes/stixRelationship-registrationAttributes';
import './attributes/stixCoreRelationship-registrationAttributes';
import './attributes/stixCyberObservable-registrationAttributes';
import './attributes/stixRefRelationship-registrationAttributes';
import './attributes/stixMetaObject-registrationAttributes';
import './attributes/stixSightingRelationship-registrationAttributes';
// endregion

// region static registration ref, need to be imported before any other modules
import './relationsRef/stixCyberObservable-registrationRef';
import './relationsRef/stixDomainObject-registrationRef';
import './relationsRef/stixRelationship-registrationRef';
// endregion

// region static graphql modules
import './channel/channel';
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
import './case/case-template/case-template';
import './case/case-incident/case-incident';
import './case/case-rfi/case-rfi';
import './case/case-rft/case-rft';
import './case/feedback/feedback';
import './entitySetting/entitySetting';
import './workspace/workspace';
import './malwareAnalysis/malwareAnalysis';
import './threatActorIndividual/threatActorIndividual';
// endregion
