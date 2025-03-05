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
import conf, { logApp } from '../../config/conf';
import {
  createInjectInScenario as obasCreateInjectInScenario,
  createScenario as obasCreateScenario,
  getAttackPatterns as obasGetAttackPatterns,
  getKillChainPhases as obasGetKillChainPhases,
  getScenarioResult as obasGetScenarioResult,
  searchInjectorContracts as obasSearchInjectorContracts
} from '../../database/xtm-obas';
import { isNotEmptyField } from '../../database/utils';
import { checkEnterpriseEdition } from '../../enterprise-edition/ee';
import { extractEntityRepresentativeName, extractRepresentativeDescription } from '../../database/entity-representative';
import { ENTITY_TYPE_LABEL } from '../../schema/stixMetaObject';
import { RELATION_TARGETS, RELATION_USES } from '../../schema/stixCoreRelationship';
import { ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL } from '../threatActorIndividual/threatActorIndividual-types';
import { queryAi } from '../../database/ai-llm';
import { getDraftContext } from '../../utils/draftContext';
import { resolveFiles } from '../../utils/ai/dataResolutionHelpers';

const XTM_OPENBAS_URL = conf.get('xtm:openbas_url');
const SYSTEM_PROMPT = 'You are an assistant helping cybersecurity engineer to select attack simulation elements and actions based on the given threat intelligence information.';
const RESOLUTION_LIMIT = 50;
const obasManualContractId = 'd02e9132-b9d0-4daa-b3b1-4b9871f8472c';
const obasEmailContractId = '2790bd39-37d4-4e39-be7e-53f3ca783f86';
const obasInjectorType = 'openbas_email';

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
    if (containers) {
      const allFilesPromise = containers.slice(0, 15).map((container) => resolveFiles(context, user, container));
      const allFiles = await Promise.all(allFilesPromise);
      files = allFiles.flat();
      names = containers.map((n) => n.name);
      descriptions = containers.map((n) => n.description);
    }
  }

  return [...names, ...descriptions, ...files.map((n) => n.content)].join(' ');
};

const generateTechnicalAttackPattern = async (obasAttackPattern, finalObasInjectorContract, scenarioId, dependsOnDuration) => {
  const obasInjectorContractContent = JSON.parse(finalObasInjectorContract.injector_contract_content);
  const title = `[${obasAttackPattern.attack_pattern_external_id}] ${obasAttackPattern.attack_pattern_name} - ${finalObasInjectorContract.injector_contract_labels.en}`;
  await obasCreateInjectInScenario(
    scenarioId,
    obasInjectorContractContent.config.type,
    finalObasInjectorContract.injector_contract_id,
    title,
    dependsOnDuration,
    null,
    [{ value: 'opencti', color: '#001bda' }, { value: 'technical', color: '#b9461a' }]
  );
};

const generatePlaceholder = async (externalId, platforms, architecture, scenarioId, dependsOnDuration) => {
  const title = `[${externalId}] Placeholder - ${platforms.join(',')} ${architecture}`;
  await obasCreateInjectInScenario(
    scenarioId,
    'openbas_manual',
    obasManualContractId,
    title,
    dependsOnDuration,
    null,
    [{ value: 'opencti', color: '#001bda' }, { value: 'technical', color: '#b9461a' }],
    false,
    `This placeholder is disabled because the TTP ${externalId} with platforms ${platforms.join(',')} and architecture ${architecture} is currently not covered. Please create the payloads for the missing TTPs.`,
  );
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
  const responseIncidentResponse = await queryAi(null, SYSTEM_PROMPT, promptIncidentResponse, user);
  const promptIncidentResponseSubject = `
            # Instructions
            - Generate a subject for the following email.
            - The subject should be short and comprehensible.
            - Just output the subject and nothing else.
            - Ensure that all words are accurately spelled and that the grammar is correct.
            
            # Email content
            ${responseIncidentResponse}
            `;
  const responseIncidentResponseSubject = await queryAi(null, SYSTEM_PROMPT, promptIncidentResponseSubject, user);
  const titleIncidentResponse = `[${killChainPhaseName}] ${obasAttackPattern.attack_pattern_name} - Email to the incident response team`;
  await obasCreateInjectInScenario(
    obasScenario.scenario_id,
    obasInjectorType,
    obasEmailContractId,
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
  const responseCiso = await queryAi(null, SYSTEM_PROMPT, promptCiso, user);
  const promptCisoSubject = `
            # Instructions
            - Generate a subject for the following email.
            - The subject should be short and comprehensible.
            - Just output the subject and nothing else.
            - Ensure that all words are accurately spelled and that the grammar is correct.
            
            # Email content
            ${responseCiso}
            `;
  const responseCisoSubject = await queryAi(null, SYSTEM_PROMPT, promptCisoSubject, user);
  const titleCiso = `[${killChainPhaseName}] ${obasAttackPattern.attack_pattern_name} - Email to the CISO`;

  await obasCreateInjectInScenario(
    obasScenario.scenario_id,
    obasInjectorType,
    obasEmailContractId,
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
  const responseCiso = await queryAi(null, SYSTEM_PROMPT, promptCiso, user);
  const promptCisoSubject = `
            # Instructions
            - Generate a subject for the following email.
            - The subject should be short and comprehensible.
            - Just output the subject and nothing else.
            - Ensure that all words are accurately spelled and that the grammar is correct.
            
            # Email content
            ${responseCiso}
            `;
  const responseCisoSubject = await queryAi(null, SYSTEM_PROMPT, promptCisoSubject, user);
  const titleCiso = `[${killChainPhaseName}] ${responseCisoSubject} - Email to the CISO`;
  await obasCreateInjectInScenario(
    obasScenario.scenario_id,
    obasInjectorType,
    obasEmailContractId,
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
  const responseIncidentResponse = await queryAi(null, SYSTEM_PROMPT, promptIncidentResponse, user);
  const promptIncidentResponseSubject = `
            # Instructions
            - Generate a subject for the following email.
            - The subject should be short and comprehensible.
            - Just output the subject and nothing else.
            - Ensure that all words are accurately spelled and that the grammar is correct.
            
            # Email content
            ${responseIncidentResponse}
            `;
  const responseIncidentResponseSubject = await queryAi(null, SYSTEM_PROMPT, promptIncidentResponseSubject, user);
  const titleIncidentResponse = `[${killChainPhaseName}] ${responseIncidentResponseSubject} - Email to the incident response team`;
  await obasCreateInjectInScenario(
    obasScenario.scenario_id,
    obasInjectorType,
    obasEmailContractId,
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

export const generateOpenBasScenarioWithInjectPlaceholders = async (
  context,
  user,
  stixCoreObject,
  attackPatterns,
  labels,
  author,
  simulationConfig
) => {
  const { interval, selection, simulationType = 'technical', platforms = ['Windows'], architecture = 'x86_64' } = simulationConfig;
  // Initialize an array to collect attack patterns without contracts
  let hasInjectPlaceholders = true;
  const attackPatternsNotAvailableInOpenBAS = [];

  if (simulationType !== 'technical') {
    await checkEnterpriseEdition(context);
  }

  const startingTime = new Date().getTime();
  logApp.info('[OPENCTI-MODULE][XTM] Starting to generate OBAS scenario', { simulationType });
  const content = await resolveContent(context, user, stixCoreObject);
  const finalAttackPatterns = attackPatterns.slice(0, RESOLUTION_LIMIT);

  // Create the scenario
  const name = `[${stixCoreObject.entity_type}] ${extractEntityRepresentativeName(stixCoreObject)}`;
  const description = extractRepresentativeDescription(stixCoreObject);
  const subtitle = `Based on cyber threat knowledge authored by ${author.name}`;

  // call to OpenBAS
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
  const obasKillChainPhases = await obasGetKillChainPhases();
  const sortedObasKillChainPhases = obasKillChainPhases.sort((a, b) => a.phase_order - b.phase_order);
  const killChainPhasesListOfNames = sortedObasKillChainPhases.map((n) => n.phase_name).join(', ');
  const indexedSortedObasKillChainPhase = sortedObasKillChainPhases.reduce((acc, phase) => {
    acc[phase.phase_id] = phase;
    return acc;
  }, {});

  const createAndInjectScenarioPromises = [];

  let dependsOnDuration = 0;
  if (attackPatterns.length === 0) {
    if (simulationType === 'simulated') {
      // eslint-disable-next-line no-restricted-syntax
      for (const obasKillChainPhase of sortedObasKillChainPhases) {
        const killChainPhaseName = obasKillChainPhase.phase_name;
        createAndInjectScenarioPromises.push(generateKillChainEmail(killChainPhaseName, killChainPhasesListOfNames, content, user, obasScenario, dependsOnDuration));
        dependsOnDuration += (interval * 60);
        createAndInjectScenarioPromises.push(generateKillChainEmailCiso(killChainPhaseName, killChainPhasesListOfNames, content, user, obasScenario, dependsOnDuration));
        dependsOnDuration += (interval * 60);
      }
    } else {
      logApp.info('[OPENCTI-MODULE][XTM] No attack pattern associated to this entity. Please use AI to generate the scenario. This feature will be enhanced in the future to cover more types of entities.');
    }
  } else {
    logApp.info('[OPENCTI-MODULE][XTM] Attack pattern found, no generation of kill chain phase email');
  }

  // Get contracts from OpenBAS related to found attack patterns

  // Get attack patterns
  const obasAttackPatterns = await obasGetAttackPatterns();

  // Extract attack patterns
  const attackPatternsMitreIds = finalAttackPatterns.filter((n) => isNotEmptyField(n.x_mitre_id)).map((n) => n.x_mitre_id);

  // Keep only attack patterns matching the container ones
  const filteredObasAttackPatterns = obasAttackPatterns.filter((n) => attackPatternsMitreIds.includes(n.attack_pattern_external_id));

  if (filteredObasAttackPatterns.length === 0) {
    hasInjectPlaceholders = false;
    let attackPatternsForPlaceholders = attackPatternsMitreIds;
    if (attackPatternsMitreIds.length === 0) {
      const attackPatternsNames = finalAttackPatterns.filter((n) => isNotEmptyField(n.name)).map((n) => n.name);
      attackPatternsForPlaceholders = attackPatternsNames;
      attackPatternsNotAvailableInOpenBAS.push(attackPatternsNames);
      logApp.info(`[OPENCTI-MODULE][XTM] No external ID for : ${attackPatternsNames.join(', ')}`);
    } else {
      attackPatternsNotAvailableInOpenBAS.push(attackPatternsMitreIds);
      logApp.info(`[OPENCTI-MODULE][XTM] No attack patterns available on OpenBAS linked to these Mitre ids : ${attackPatternsMitreIds.join(', ')}`);
    }
    if (simulationType !== 'simulated') {
      hasInjectPlaceholders = true;
      attackPatternsForPlaceholders.forEach((attackNotAvailable) => {
        createAndInjectScenarioPromises.push(generatePlaceholder(
          attackNotAvailable,
          platforms,
          architecture,
          obasScenario.scenario_id,
          dependsOnDuration
        ));
        dependsOnDuration += (interval * 60);
      });
    }
  } else {
    // Enrich with the earliest kill chain phase
    const enrichedFilteredObasAttackPatterns = filteredObasAttackPatterns.map((n) => {
      const earliestKillChainPhase = n.attack_pattern_kill_chain_phases
        .map((phaseId) => indexedSortedObasKillChainPhase[phaseId])
        .sort((a, b) => a.phase_order - b.phase_order)[0];
      return { ...n, attack_pattern_kill_chain_phase: earliestKillChainPhase };
    });

    // Sort attack pattern by kill chain phase
    const sortedEnrichedFilteredObasAttackPatterns = enrichedFilteredObasAttackPatterns.sort((a, b) => {
      return a.attack_pattern_kill_chain_phase.phase_order - b.attack_pattern_kill_chain_phase.phase_order;
    });

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
        const obasInjectorContracts = await obasSearchInjectorContracts(obasAttackPattern.attack_pattern_external_id, platforms, architecture);
        if (obasInjectorContracts.length === 0) {
          attackPatternsNotAvailableInOpenBAS.push(obasAttackPattern.attack_pattern_external_id);
          logApp.info(`[OPENCTI-MODULE][XTM] No injector contracts available for this attack pattern ${obasAttackPattern.attack_pattern_external_id}`);
          createAndInjectScenarioPromises.push(generatePlaceholder(
            obasAttackPattern.attack_pattern_external_id,
            platforms,
            architecture,
            obasScenario.scenario_id,
            dependsOnDuration
          ));
          dependsOnDuration += (interval * 60);
        } else {
          let finalObasInjectorContracts = getShuffledArr(obasInjectorContracts).slice(0, 5);
          if (selection === 'random') {
            finalObasInjectorContracts = finalObasInjectorContracts.slice(0, 1);
          }
          if (simulationType === 'technical') {
            // eslint-disable-next-line no-restricted-syntax
            for (const finalObasInjectorContract of finalObasInjectorContracts) {
              createAndInjectScenarioPromises.push(generateTechnicalAttackPattern(obasAttackPattern, finalObasInjectorContract, obasScenario.scenario_id, dependsOnDuration));
              dependsOnDuration += (interval * 60);
            }
          } else {
            // TODO CASE Mixed (both)
            logApp.info(`[OPENCTI-MODULE][XTM] simulationType ${simulationType} not implemented yet.`);
          }
        }
      }
    } // end loop for

    await Promise.all(createAndInjectScenarioPromises).catch((error) => logApp.error('[OPENCTI-MODULE][XTM] Error resolving promises', { error }));

    const endingTime = new Date().getTime();
    const totalTime = endingTime - startingTime;
    if (totalTime > 120000) {
      logApp.warn('[OPENCTI-MODULE][XTM] Long scenario generation time', {
        size: createAndInjectScenarioPromises.length,
        took: totalTime,
        simulationType
      });
    }

    logApp.info(`[OPENCTI-MODULE][XTM] Generating ${createAndInjectScenarioPromises.length} injects took ${totalTime} ms`, { simulationType });
  }

  return {
    urlResponse: `${XTM_OPENBAS_URL}/admin/scenarios/${obasScenario.scenario_id}/injects`,
    attackPatternsNotAvailableInOpenBAS: attackPatternsNotAvailableInOpenBAS.join(','),
    hasInjectPlaceholders,
  };
};

export const generateContainerScenarioWithInjectPlaceholders = async (context, user, args) => {
  if (getDraftContext(context, user)) throw new Error('Cannot generate scenario in draft');
  const { id, simulationConfig } = args;

  const container = await storeLoadById(context, user, id, ENTITY_TYPE_CONTAINER);
  const author = await listAllToEntitiesThroughRelations(context, user, id, RELATION_CREATED_BY, [ENTITY_TYPE_IDENTITY]);
  const labels = await listAllToEntitiesThroughRelations(context, user, id, RELATION_OBJECT_LABEL, [ENTITY_TYPE_LABEL]);
  const attackPatterns = await listAllToEntitiesThroughRelations(context, user, id, RELATION_OBJECT, [ENTITY_TYPE_ATTACK_PATTERN]);
  return generateOpenBasScenarioWithInjectPlaceholders(context, user, container, attackPatterns, labels, (author && author.length > 0 ? author.at(0) : 'Unknown'), simulationConfig);
};

export const generateThreatScenarioWithInjectPlaceholders = async (context, user, args) => {
  if (getDraftContext(context, user)) throw new Error('Cannot generate scenario in draft');
  const { id, simulationConfig } = args;

  const stixCoreObject = await storeLoadById(context, user, id, ABSTRACT_STIX_DOMAIN_OBJECT);
  const labels = await listAllToEntitiesThroughRelations(context, user, id, RELATION_OBJECT_LABEL, [ENTITY_TYPE_LABEL]);
  const author = await listAllToEntitiesThroughRelations(context, user, id, RELATION_CREATED_BY, [ENTITY_TYPE_IDENTITY]);
  const attackPatterns = await listAllToEntitiesThroughRelations(context, user, id, RELATION_USES, [ENTITY_TYPE_ATTACK_PATTERN]);
  return generateOpenBasScenarioWithInjectPlaceholders(context, user, stixCoreObject, attackPatterns, labels, (author && author.length > 0 ? author.at(0) : 'Unknown'), simulationConfig);
};

export const generateVictimScenarioWithInjectPlaceholders = async (context, user, args) => {
  if (getDraftContext(context, user)) throw new Error('Cannot generate scenario in draft');
  const { id, simulationConfig } = args;

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
  return generateOpenBasScenarioWithInjectPlaceholders(context, user, stixCoreObject, attackPatterns, labels, (author && author.length > 0 ? author.at(0) : 'Unknown'), simulationConfig);
};
