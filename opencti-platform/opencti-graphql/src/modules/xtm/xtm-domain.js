import * as R from 'ramda';
import { listAllToEntitiesThroughRelations, storeLoadById } from '../../database/middleware-loader';
import { ABSTRACT_STIX_DOMAIN_OBJECT, buildRefRelationKey, ENTITY_TYPE_CONTAINER, ENTITY_TYPE_IDENTITY } from '../../schema/general';
import { RELATION_CREATED_BY, RELATION_OBJECT, RELATION_OBJECT_LABEL } from '../../schema/stixRefRelationship';
import { addFilter } from '../../utils/filtering/filtering-utils';
import { distributionEntities } from '../../database/middleware';
import {
  ENTITY_TYPE_ATTACK_PATTERN,
  ENTITY_TYPE_CAMPAIGN,
  ENTITY_TYPE_CONTAINER_REPORT,
  ENTITY_TYPE_INCIDENT,
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_THREAT_ACTOR_GROUP
} from '../../schema/stixDomainObject';
import { UnsupportedError } from '../../config/errors';
import conf, { logApp } from '../../config/conf';
import {
  createInjectInScenario as obasCreateInjectInScenario,
  createScenario as obasCreateScenario,
  getAttackPatterns as obasGetAttackPatterns,
  getInjectorContracts as obasGetInjectorContracts,
  getKillChainPhases as obasGetKillChainPhases,
  getScenarioResult as obasGetScenarioResult,
} from '../../database/xtm-obas';
import { isNotEmptyField } from '../../database/utils';
import { checkEnterpriseEdition } from '../../enterprise-edition/ee';
import { paginatedForPathWithEnrichment } from '../internal/document/document-domain';
import { elSearchFiles } from '../../database/file-search';
import { extractEntityRepresentativeName, extractRepresentativeDescription } from '../../database/entity-representative';
import { ENTITY_TYPE_LABEL } from '../../schema/stixMetaObject';
import { RELATION_TARGETS, RELATION_USES } from '../../schema/stixCoreRelationship';
import { ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL } from '../threatActorIndividual/threatActorIndividual-types';
import { queryAi } from '../../database/ai-llm';
import { getDraftContext } from '../../utils/draftContext';

const XTM_OPENBAS_URL = conf.get('xtm:openbas_url');
const RESOLUTION_LIMIT = 50;

const getShuffledArr = (arr) => {
  const newArr = arr.slice();
  // eslint-disable-next-line no-plusplus
  for (let i = newArr.length - 1; i > 0; i--) {
    const rand = Math.floor(Math.random() * (i + 1));
    [newArr[i], newArr[rand]] = [newArr[rand], newArr[i]];
  }
  return newArr;
};

export const stixCoreObjectSimulationsResult = async (_, __, args) => {
  const { id } = args;
  return obasGetScenarioResult(id);
};

export const scenarioElementsDistribution = async (context, user, args) => {
  const { id } = args;
  const filters = addFilter(args.filters, buildRefRelationKey('*', '*'), id);
  return distributionEntities(context, user, [ABSTRACT_STIX_DOMAIN_OBJECT], { field: 'entity_type', filters });
};

export const resolveFiles = async (context, user, stixCoreObject) => {
  const opts = {
    first: 1,
    prefixMimeTypes: undefined,
    entity_id: stixCoreObject.id,
    entity_type: stixCoreObject.entity_type
  };
  const importFiles = await paginatedForPathWithEnrichment(context, user, `import/${stixCoreObject.entity_type}/${stixCoreObject.id}`, stixCoreObject.id, opts);
  const fileIds = importFiles.edges.map((n) => n.node.id);
  if (fileIds.length === 0) {
    return [];
  }
  const files = await elSearchFiles(context, user, {
    first: 1,
    fileIds,
    connectionFormat: false,
    excludeFields: [],
    includeContent: true
  });
  return files;
};

export const resolveContent = async (context, user, stixCoreObject) => {
  let names = [];
  let descriptions = [];
  let files = [];
  if (stixCoreObject.parent_types.includes(ENTITY_TYPE_CONTAINER)) {
    names = [stixCoreObject.name];
    descriptions = [stixCoreObject.description];
    files = await resolveFiles(context, user, stixCoreObject);
  } else {
    const containers = await listAllToEntitiesThroughRelations(context, user, stixCoreObject.id, RELATION_OBJECT, [ENTITY_TYPE_CONTAINER_REPORT]);
    const allFiles = await Promise.all(R.take(15, containers).map((container) => resolveFiles(context, user, container)));
    files = allFiles.flat();
    names = containers.map((n) => n.name);
    descriptions = containers.map((n) => n.description);
  }

  const result = [...names, ...descriptions, ...files.map((n) => n.content)].join(' ');
  return result;
};
const generateTechnicalAttackPattern = async (obasAttackPattern, selection, simulationType, obasScenario, dependsOnDuration, interval) => {
  let dependsOnDurationLocal = dependsOnDuration;
  const obasInjectorContracts = await obasGetInjectorContracts(obasAttackPattern.attack_pattern_id);
  let finalObasInjectorContracts = R.take(5, getShuffledArr(obasInjectorContracts));
  if (selection === 'random') {
    finalObasInjectorContracts = R.take(1, finalObasInjectorContracts);
  }
  if (simulationType === 'technical') {
    // eslint-disable-next-line no-restricted-syntax
    for (const finalObasInjectorContract of finalObasInjectorContracts) {
      const obasInjectorContractContent = JSON.parse(finalObasInjectorContract.injector_contract_content);
      const title = `[${obasAttackPattern.attack_pattern_external_id}] ${obasAttackPattern.attack_pattern_name} - ${finalObasInjectorContract.injector_contract_labels.en}`;
      await obasCreateInjectInScenario(
        obasScenario.scenario_id,
        obasInjectorContractContent.config.type,
        finalObasInjectorContract.injector_contract_id,
        title,
        dependsOnDurationLocal,
        null,
        [{ value: 'opencti', color: '#001bda' }, { value: 'technical', color: '#b9461a' }]
      );
      dependsOnDurationLocal += (interval * 60);
    }
  } else {
    // TODO
    logApp.info(`[OPENCTI-MODULE][XTM] simulationType ${simulationType} not implemented yet.`);
  }
};

const generateAttackPatternEmail = async (obasAttackPattern, killChainPhaseName, killChainPhasesListOfNames, content, user, obasScenario, dependsOnDuration) => {
// Mail to incident response
  const promptIncidentResponse = `
            # Instructions
            - The context is a cybersecurity breach and attack simulation and cybersecurity crisis management exercise
            - The enterprise is under attack! The incident response team and the CISO will need to answer to fake injections and questions.
            - You should fake it and not writing about the simulation but like if it is a true cybersecurity threat and / or incident.
            - Order of kill chain phases is ${killChainPhasesListOfNames}.
            - Examine the provided content which describes an attack technique in the context of the kill chain phase ${killChainPhaseName}.
            - You should take into account the context about the attack.
            - You should write an email message (only the content, NOT the subject) representing this attack technique targeting the enterprise of 3 paragraphs with 3 lines in each paragraph in HTML.
            - The email message should be addressed from the security operation center team to the incident response team, talking about the phase of the attack.
            - The incident response team is under attack.
            - Ensure that all words are accurately spelled and that the grammar is correct.
            - Your response should be in HTML format. Be sure to respect this format and to NOT output anything else than the format.
            
            # Context about the attack
            ${content}
            
            # Content
            ${obasAttackPattern.attack_pattern_description}
            `;
  const responseIncidentResponse = await queryAi(null, promptIncidentResponse, user);
  const promptIncidentResponseSubject = `
            # Instructions
            - Generate a subject for the following email.
            - The subject should be short and comprehensible.
            - Just output the subject and nothing else.
            - Ensure that all words are accurately spelled and that the grammar is correct.
            
            # Email content
            ${responseIncidentResponse}
            `;
  const responseIncidentResponseSubject = await queryAi(null, promptIncidentResponseSubject, user);
  const titleIncidentResponse = `[${killChainPhaseName}] ${obasAttackPattern.attack_pattern_name} - Email to the incident response team`;
  await obasCreateInjectInScenario(
    obasScenario.scenario_id,
    'openbas_email',
    '2790bd39-37d4-4e39-be7e-53f3ca783f86',
    titleIncidentResponse,
    dependsOnDuration,
    { expectations: [], subject: responseIncidentResponseSubject.replace('Subject: ', '').replace('"', ''), body: responseIncidentResponse },
    [{ value: 'opencti', color: '#001bda' }, { value: 'csirt', color: '#c28b0d' }]
  );
};

const generateAttackPatternEmailCiso = async (obasAttackPattern, killChainPhaseName, killChainPhasesListOfNames, content, user, obasScenario, dependsOnDuration) => {
  const promptCiso = `
            # Instructions
            - The context is a cybersecurity breach and attack simulation and cybersecurity crisis management exercise
            - The enterprise is under attack! The incident response team and the CISO will need to answer to fake injections and questions.
            - You should fake it and not writing about the simulation but like if it is a true cybersecurity threat and / or incident.
            - Order of kill chain phases is ${killChainPhasesListOfNames}.
            - Examine the provided content which describes an attack technique in the context of the kill chain phase ${killChainPhaseName}.
            - You should write an email message (only the content, NOT the subject) representing this attack technique targeting the enterprise of 3 paragraphs with 3 lines in each paragraph in HTML.
            - You should take into account the context about the attack.
            - The email message should be addressed from the security operation center team to the chief information security officer.
            - The CISO is under attack.
            - Ensure that all words are accurately spelled and that the grammar is correct.
            - Your response should be in HTML format. Be sure to respect this format and to NOT output anything else than the format.
          
            # Context about the attack
            ${content}
            
            # Content
            ${obasAttackPattern.attack_pattern_description}
        `;
  const responseCiso = await queryAi(null, promptCiso, user);
  const promptCisoSubject = `
            # Instructions
            - Generate a subject for the following email.
            - The subject should be short and comprehensible.
            - Just output the subject and nothing else.
            - Ensure that all words are accurately spelled and that the grammar is correct.
            
            # Email content
            ${responseCiso}
            `;
  const responseCisoSubject = await queryAi(null, promptCisoSubject, user);
  const titleCiso = `[${killChainPhaseName}] ${obasAttackPattern.attack_pattern_name} - Email to the CISO`;

  await obasCreateInjectInScenario(
    obasScenario.scenario_id,
    'openbas_email',
    '2790bd39-37d4-4e39-be7e-53f3ca783f86',
    titleCiso,
    dependsOnDuration,
    { expectations: [], subject: responseCisoSubject.replace('Subject: ', '').replace('"', ''), body: responseCiso },
    [{ value: 'opencti', color: '#001bda' }, { value: 'ciso', color: '#b41313' }]
  );
};

const generateKillChainEmailCiso = async (killChainPhaseName, killChainPhasesListOfNames, content, user, obasScenario, dependsOnDuration) => {
// Mail to CISO
  const promptCiso = `
            # Instructions
            - The context is a cybersecurity breach and attack simulation and cybersecurity crisis management exercise
            - The enterprise is under attack! The incident response team and the CISO will need to answer to fake injections and questions.
            - You should fake it and not writing about the simulation but like if it is a true cybersecurity threat and / or incident.
            - Order of kill chain phases is ${killChainPhasesListOfNames}.
            - We are in the kill chain phase ${killChainPhaseName}.
            - You should write an email message (only the content, NOT the subject) representing this kill chain phase (${killChainPhaseName}) targeting the enterprise of 3 paragraphs with 3 lines in each paragraph in HTML.
            - The email message should be addressed from the security operation center team to the chief security officer, talking about the phase of the attack.
            - The incident response team is under attack.
            - Ensure that all words are accurately spelled and that the grammar is correct.
            - Your response should be in HTML format. Be sure to respect this format and to NOT output anything else than the format.
            
            # Context about the attack
            ${content}
            `;
  const responseCiso = await queryAi(null, promptCiso, user);
  const promptCisoSubject = `
            # Instructions
            - Generate a subject for the following email.
            - The subject should be short and comprehensible.
            - Just output the subject and nothing else.
            - Ensure that all words are accurately spelled and that the grammar is correct.
            
            # Email content
            ${responseCiso}
            `;
  const responseCisoSubject = await queryAi(null, promptCisoSubject, user);
  const titleCiso = `[${killChainPhaseName}] ${responseCisoSubject} - Email to the CISO`;
  await obasCreateInjectInScenario(
    obasScenario.scenario_id,
    'openbas_email',
    '2790bd39-37d4-4e39-be7e-53f3ca783f86',
    titleCiso,
    dependsOnDuration,
    {
      expectations: [],
      subject: responseCisoSubject.replace('Subject: ', '').replace('"', ''),
      body: responseCiso
    },
    [{ value: 'opencti', color: '#001bda' }, { value: 'ciso', color: '#b41313' }]
  );
};

const generateKillChainEmail = async (killChainPhaseName, killChainPhasesListOfNames, content, user, obasScenario, dependsOnDuration) => {
  // Mail to incident response
  const promptIncidentResponse = `
            # Instructions
            - The context is a cybersecurity breach and attack simulation and cybersecurity crisis management exercise
            - The enterprise is under attack! The incident response team and the CISO will need to answer to fake injections and questions.
            - You should fake it and not writing about the simulation but like if it is a true cybersecurity threat and / or incident.
            - Order of kill chain phases is ${killChainPhasesListOfNames}.
            - We are in the kill chain phase ${killChainPhaseName}.
            - You should write an email message (only the content, NOT the subject) representing this kill chain phase (${killChainPhaseName}) targeting the enterprise of 3 paragraphs with 3 lines in each paragraph in HTML.
            - The email message should be addressed from the security operation center team to the incident response team, talking about the phase of the attack.
            - The incident response team is under attack.
            - Ensure that all words are accurately spelled and that the grammar is correct and the output format is in HTML.
            - Your response should be in HTML format. Be sure to respect this format and to NOT output anything else than the format.
            
            # Context about the attack
            ${content}
            `;
  const responseIncidentResponse = await queryAi(null, promptIncidentResponse, user);
  const promptIncidentResponseSubject = `
            # Instructions
            - Generate a subject for the following email.
            - The subject should be short and comprehensible.
            - Just output the subject and nothing else.
            - Ensure that all words are accurately spelled and that the grammar is correct.
            
            # Email content
            ${responseIncidentResponse}
            `;
  const responseIncidentResponseSubject = await queryAi(null, promptIncidentResponseSubject, user);
  const titleIncidentResponse = `[${killChainPhaseName}] ${responseIncidentResponseSubject} - Email to the incident response team`;
  await obasCreateInjectInScenario(
    obasScenario.scenario_id,
    'openbas_email',
    '2790bd39-37d4-4e39-be7e-53f3ca783f86',
    titleIncidentResponse,
    dependsOnDuration,
    {
      expectations: [],
      subject: responseIncidentResponseSubject.replace('Subject: ', '').replace('"', ''),
      body: responseIncidentResponse
    },
    [{ value: 'opencti', color: '#001bda' }, { value: 'csirt', color: '#c28b0d' }]
  );
};

export const generateOpenBasScenario = async (context, user, stixCoreObject, attackPatterns, labels, author, simulationType, interval, selection, useAI) => {
  const startingTime = new Date().getTime();
  logApp.info('[OPENCTI-MODULE][XTM] Starting to generate OBAS scenario', { useAI, simulationType });
  const content = await resolveContent(context, user, stixCoreObject);
  const finalAttackPatterns = R.take(RESOLUTION_LIMIT, attackPatterns);

  // Create the scenario
  const name = `[${stixCoreObject.entity_type}] ${extractEntityRepresentativeName(stixCoreObject)}`;
  const description = extractRepresentativeDescription(stixCoreObject);
  const subtitle = `Based on cyber threat knowledge authored by ${author.name}`;

  // call to obas
  const obasScenario = await obasCreateScenario(
    name,
    subtitle,
    description,
    [...labels, { value: 'opencti', color: '#001bda' }],
    stixCoreObject.id,
    stixCoreObject.entity_type,
    simulationType === 'simulated' ? 'global-crisis' : 'attack-scenario'
  );

  // Get kill chain phases
  const sortByPhaseOrder = R.sortBy(R.prop('phase_order'));
  const obasKillChainPhases = await obasGetKillChainPhases(); // Why it's not called only inside  if (attackPatterns.length === 0)  ??
  const sortedObasKillChainPhases = sortByPhaseOrder(obasKillChainPhases);
  const killChainPhasesListOfNames = sortedObasKillChainPhases.map((n) => n.phase_name).join(', ');
  const indexedSortedObasKillChainPhase = R.indexBy(R.prop('phase_id'), sortedObasKillChainPhases);

  const createAndInjectScenarioPromises = [];

  let dependsOnDuration = 0;
  if (attackPatterns.length === 0) {
    if (!useAI) {
      throw UnsupportedError('No attack pattern associated to this entity. Please use AI to generate the scenario. This feature will be enhanced in the future to cover more types of entities.');
    }
    // eslint-disable-next-line no-restricted-syntax
    for (const obasKillChainPhase of sortedObasKillChainPhases) {
      const killChainPhaseName = obasKillChainPhase.phase_name;
      createAndInjectScenarioPromises.push(generateKillChainEmail(killChainPhaseName, killChainPhasesListOfNames, content, user, obasScenario, dependsOnDuration));
      dependsOnDuration += (interval * 60);
      createAndInjectScenarioPromises.push(generateKillChainEmailCiso(killChainPhaseName, killChainPhasesListOfNames, content, user, obasScenario, dependsOnDuration));
      dependsOnDuration += (interval * 60);
    }
  } else {
    logApp.debug('[OPENCTI-MODULE][XTM] attack pattern found, no generation of kill chain phase email');
  }
  // Get contracts from OpenBAS related to found attack patterns

  // Get attack patterns
  const obasAttackPatterns = await obasGetAttackPatterns();

  // Extract attack patterns
  const attackPatternsMitreIds = finalAttackPatterns.filter((n) => isNotEmptyField(n.x_mitre_id)).map((n) => n.x_mitre_id);

  // Keep only attack patterns matching the container ones
  const filteredObasAttackPatterns = obasAttackPatterns.filter((n) => attackPatternsMitreIds.includes(n.attack_pattern_external_id));

  // Enrich with the earliest kill chain phase
  const enrichedFilteredObasAttackPatterns = filteredObasAttackPatterns.map(
    (n) => R.assoc('attack_pattern_kill_chain_phase', sortByPhaseOrder(n.attack_pattern_kill_chain_phases.map((o) => indexedSortedObasKillChainPhase[o])).at(0), n)
  );

  // Sort attack pattern by kill chain phase
  const sortByKillChainPhase = R.sortBy(R.path(['attack_pattern_kill_chain_phase', 'phase_order']));
  const sortedEnrichedFilteredObasAttackPatterns = sortByKillChainPhase(enrichedFilteredObasAttackPatterns);

  // Get the injector contracts
  // eslint-disable-next-line no-restricted-syntax
  for (const obasAttackPattern of sortedEnrichedFilteredObasAttackPatterns) {
    const killChainPhaseName = obasAttackPattern.attack_pattern_kill_chain_phase.phase_name;
    if (simulationType === 'simulated') {
      createAndInjectScenarioPromises.push(
        generateAttackPatternEmail(obasAttackPattern, killChainPhaseName, killChainPhasesListOfNames, content, user, obasScenario, dependsOnDuration)
      );
      dependsOnDuration += (interval * 60);
      createAndInjectScenarioPromises.push(
        generateAttackPatternEmailCiso(obasAttackPattern, killChainPhaseName, killChainPhasesListOfNames, content, user, obasScenario, dependsOnDuration)
      );
      dependsOnDuration += (interval * 60);
    } else {
      createAndInjectScenarioPromises.push(generateTechnicalAttackPattern(obasAttackPattern, selection, simulationType, obasScenario, dependsOnDuration, interval));
      dependsOnDuration += (interval * 60);
    }
  } // end loop for
  await Promise.all(createAndInjectScenarioPromises);

  const endingTime = new Date().getTime();
  const totalTime = endingTime - startingTime;
  if (totalTime > 120000) {
    logApp.warn(`[OPENCTI-MODULE][XTM] Long scenario generation time. Generating ${createAndInjectScenarioPromises.length} emails took ${totalTime} ms`, { useAI, simulationType });
  }
  logApp.info(`[OPENCTI-MODULE][XTM] Generating ${createAndInjectScenarioPromises.length} emails took ${totalTime} ms`, { useAI, simulationType });
  return `${XTM_OPENBAS_URL}/admin/scenarios/${obasScenario.scenario_id}/injects`;
};

export const generateContainerScenario = async (context, user, args) => {
  if (getDraftContext(context, user)) throw new Error('Cannot generate scenario in draft');
  const { id, interval, selection, simulationType = 'technical', useAI = false } = args;
  if (useAI || simulationType !== 'technical') {
    await checkEnterpriseEdition(context);
  }
  const container = await storeLoadById(context, user, id, ENTITY_TYPE_CONTAINER);
  const author = await listAllToEntitiesThroughRelations(context, user, id, RELATION_CREATED_BY, [ENTITY_TYPE_IDENTITY]);
  const labels = await listAllToEntitiesThroughRelations(context, user, id, RELATION_OBJECT_LABEL, [ENTITY_TYPE_LABEL]);
  const attackPatterns = await listAllToEntitiesThroughRelations(context, user, id, RELATION_OBJECT, [ENTITY_TYPE_ATTACK_PATTERN]);
  return generateOpenBasScenario(context, user, container, attackPatterns, labels, (author && author.length > 0 ? author.at(0) : 'Unknown'), simulationType, interval, selection, useAI);
};

export const generateThreatScenario = async (context, user, args) => {
  if (getDraftContext(context, user)) throw new Error('Cannot generate scenario in draft');
  const { id, interval, selection, simulationType = 'technical', useAI = false } = args;
  if (useAI || simulationType !== 'technical') {
    await checkEnterpriseEdition(context);
  }
  const stixCoreObject = await storeLoadById(context, user, id, ABSTRACT_STIX_DOMAIN_OBJECT);
  const labels = await listAllToEntitiesThroughRelations(context, user, id, RELATION_OBJECT_LABEL, [ENTITY_TYPE_LABEL]);
  const author = await listAllToEntitiesThroughRelations(context, user, id, RELATION_CREATED_BY, [ENTITY_TYPE_IDENTITY]);
  const attackPatterns = await listAllToEntitiesThroughRelations(context, user, id, RELATION_USES, [ENTITY_TYPE_ATTACK_PATTERN]);
  return generateOpenBasScenario(context, user, stixCoreObject, attackPatterns, labels, (author && author.length > 0 ? author.at(0) : 'Unknown'), simulationType, interval, selection, useAI);
};

export const generateVictimScenario = async (context, user, args) => {
  if (getDraftContext(context, user)) throw new Error('Cannot generate scenario in draft');
  const { id, interval, selection, simulationType = 'technical', useAI = false } = args;
  if (useAI || simulationType !== 'technical') {
    await checkEnterpriseEdition(context);
  }
  const stixCoreObject = await storeLoadById(context, user, id, ABSTRACT_STIX_DOMAIN_OBJECT);
  const labels = await listAllToEntitiesThroughRelations(context, user, id, RELATION_OBJECT_LABEL, [ENTITY_TYPE_LABEL]);
  const author = await listAllToEntitiesThroughRelations(context, user, id, RELATION_CREATED_BY, [ENTITY_TYPE_IDENTITY]);
  const threats = await listAllToEntitiesThroughRelations(
    context,
    user,
    id,
    RELATION_TARGETS,
    [
      ENTITY_TYPE_THREAT_ACTOR_GROUP,
      ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL,
      ENTITY_TYPE_INTRUSION_SET,
      ENTITY_TYPE_CAMPAIGN,
      ENTITY_TYPE_INCIDENT
    ]
  );
  const threatsIds = threats.map((n) => n.id);
  const attackPatterns = await listAllToEntitiesThroughRelations(context, user, threatsIds, RELATION_USES, [ENTITY_TYPE_ATTACK_PATTERN]);
  return generateOpenBasScenario(context, user, stixCoreObject, attackPatterns, labels, (author && author.length > 0 ? author.at(0) : 'Unknown'), simulationType, interval, selection, useAI);
};
