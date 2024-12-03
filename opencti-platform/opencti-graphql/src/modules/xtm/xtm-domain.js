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
import { checkEnterpriseEdition } from '../../utils/ee';
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
  logApp.info('ANGIE - resolveContent', { result: result.toString() });
  return result;
};

export const generateOpenBasScenario = async (context, user, stixCoreObject, attackPatterns, labels, author, simulationType, interval, selection, useAI) => {
  logApp.info('[XTM] Starting to generate OBAS scenario', { useAI, simulationType });
  console.time('[XTM]generateOpenBasScenario ALL');
  const startingDate = new Date().getTime();
  const content = await resolveContent(context, user, stixCoreObject);
  const finalAttackPatterns = R.take(RESOLUTION_LIMIT, attackPatterns);

  // Create the scenario
  const name = `[${stixCoreObject.entity_type}] ${extractEntityRepresentativeName(stixCoreObject)}`;
  const description = extractRepresentativeDescription(stixCoreObject);
  const subtitle = `Based on cyber threat knowledge authored by ${author.name}`;

  // call to obas
  console.time('[XTM]obasCreateScenario1');
  const obasScenario = await obasCreateScenario(
    name,
    subtitle,
    description,
    [...labels, { value: 'opencti', color: '#001bda' }],
    stixCoreObject.id,
    stixCoreObject.entity_type,
    simulationType === 'simulated' ? 'global-crisis' : 'attack-scenario'
  );
  console.timeEnd('[XTM]obasCreateScenario1');

  // Get kill chain phases
  const sortByPhaseOrder = R.sortBy(R.prop('phase_order'));
  console.time('[XTM]obasGetKillChainPhases1');
  const obasKillChainPhases = await obasGetKillChainPhases(); // Why it's not called only inside  if (attackPatterns.length === 0)  ??
  console.timeEnd('[XTM]obasGetKillChainPhases1');
  const sortedObasKillChainPhases = sortByPhaseOrder(obasKillChainPhases);
  const killChainPhasesListOfNames = sortedObasKillChainPhases.map((n) => n.phase_name).join(', ');
  const indexedSortedObasKillChainPhase = R.indexBy(R.prop('phase_id'), sortedObasKillChainPhases);

  let dependsOnDuration = 0;
  if (attackPatterns.length === 0) {
    if (!useAI) {
      throw UnsupportedError('No attack pattern associated to this entity. Please use AI to generate the scenario. This feature will be enhanced in the future to cover more types of entities.');
    }
    console.time('[XTM]obasKillChainPhase loop');
    // eslint-disable-next-line no-restricted-syntax
    for (const obasKillChainPhase of sortedObasKillChainPhases) {
      const killChainPhaseName = obasKillChainPhase.phase_name;
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
      console.time('[XTM]queryAi-obasKillChainPhase-email');
      const responseIncidentResponse = await queryAi(null, promptIncidentResponse, user);
      console.timeEnd('[XTM]queryAi-obasKillChainPhase-email');
      const promptIncidentResponseSubject = `
            # Instructions
            - Generate a subject for the following email.
            - The subject should be short and comprehensible.
            - Just output the subject and nothing else.
            - Ensure that all words are accurately spelled and that the grammar is correct.
            
            # Email content
            ${responseIncidentResponse}
            `;
      console.time('[XTM]queryAi-obasKillChainPhase-subject');
      const responseIncidentResponseSubject = await queryAi(null, promptIncidentResponseSubject, user);
      console.timeEnd('[XTM]queryAi-obasKillChainPhase-subject');
      const titleIncidentResponse = `[${killChainPhaseName}] ${responseIncidentResponseSubject} - Email to the incident response team`;
      console.time('[XTM]obasCreateInjectInScenario-obasKillChainPhase');
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
      console.timeEnd('[XTM]obasCreateInjectInScenario-obasKillChainPhase');
      dependsOnDuration += (interval * 60);
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
      console.time('[XTM]queryAi-obasKillChainPhase-email-ciso');
      const responseCiso = await queryAi(null, promptCiso, user);
      console.timeEnd('[XTM]queryAi-obasKillChainPhase-email-ciso');
      const promptCisoSubject = `
            # Instructions
            - Generate a subject for the following email.
            - The subject should be short and comprehensible.
            - Just output the subject and nothing else.
            - Ensure that all words are accurately spelled and that the grammar is correct.
            
            # Email content
            ${responseCiso}
            `;
      console.time('[XTM]queryAi-obasKillChainPhase-subject-ciso');
      const responseCisoSubject = await queryAi(null, promptCisoSubject, user);
      console.timeEnd('[XTM]queryAi-obasKillChainPhase-subject-ciso');
      const titleCiso = `[${killChainPhaseName}] ${responseCisoSubject} - Email to the CISO`;
      console.time('[XTM]queryAi-obasKillChainPhase-obasCreateInjectInScenario-ciso');
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
      console.timeEnd('[XTM]queryAi-obasKillChainPhase-obasCreateInjectInScenario-ciso');
      dependsOnDuration += (interval * 60);
    } // end for loop
    console.timeEnd('[XTM]obasKillChainPhase loop');
  } else {
    logApp.info('[XTM] attack pattern found, no generation of kill chain phase email');
  }
  // Get contracts from OpenBAS related to found attack patterns

  // Get attack patterns
  console.time('[XTM]obasGetAttackPatterns');
  const obasAttackPatterns = await obasGetAttackPatterns();
  console.timeEnd('[XTM]obasGetAttackPatterns');

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

  console.time('[XTM]obasAttackPattern loop');
  const aiAttackPatterEmailStart = new Date().getTime();
  // Get the injector contracts
  // eslint-disable-next-line no-restricted-syntax
  for (const obasAttackPattern of sortedEnrichedFilteredObasAttackPatterns) {
    const killChainPhaseName = obasAttackPattern.attack_pattern_kill_chain_phase.phase_name;
    if (simulationType === 'simulated') {
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
      console.time('[XTM]queryAi-obasAttackPattern-email');
      const responseIncidentResponse = await queryAi(null, promptIncidentResponse, user);
      console.timeEnd('[XTM]queryAi-obasAttackPattern-email');
      const promptIncidentResponseSubject = `
            # Instructions
            - Generate a subject for the following email.
            - The subject should be short and comprehensible.
            - Just output the subject and nothing else.
            - Ensure that all words are accurately spelled and that the grammar is correct.
            
            # Email content
            ${responseIncidentResponse}
            `;
      console.time('[XTM]queryAi-obasAttackPattern-subject');
      const responseIncidentResponseSubject = await queryAi(null, promptIncidentResponseSubject, user);
      console.timeEnd('[XTM]queryAi-obasAttackPattern-subject');
      const titleIncidentResponse = `[${killChainPhaseName}] ${obasAttackPattern.attack_pattern_name} - Email to the incident response team`;
      console.time('[XTM]queryAi-obasAttackPattern-obasCreateInjectInScenario');
      await obasCreateInjectInScenario(
        obasScenario.scenario_id,
        'openbas_email',
        '2790bd39-37d4-4e39-be7e-53f3ca783f86',
        titleIncidentResponse,
        dependsOnDuration,
        { expectations: [], subject: responseIncidentResponseSubject.replace('Subject: ', '').replace('"', ''), body: responseIncidentResponse },
        [{ value: 'opencti', color: '#001bda' }, { value: 'csirt', color: '#c28b0d' }]
      );
      console.timeEnd('[XTM]queryAi-obasAttackPattern-obasCreateInjectInScenario');
      dependsOnDuration += (interval * 60);
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
      console.time('[XTM]queryAi-obasAttackPattern-email-ciso');
      const responseCiso = await queryAi(null, promptCiso, user);
      console.timeEnd('[XTM]queryAi-obasAttackPattern-email-ciso');
      const promptCisoSubject = `
            # Instructions
            - Generate a subject for the following email.
            - The subject should be short and comprehensible.
            - Just output the subject and nothing else.
            - Ensure that all words are accurately spelled and that the grammar is correct.
            
            # Email content
            ${responseCiso}
            `;
      console.time('[XTM]queryAi-obasAttackPattern-subject-ciso');
      const responseCisoSubject = await queryAi(null, promptCisoSubject, user);
      console.timeEnd('[XTM]queryAi-obasAttackPattern-subject-ciso');
      const titleCiso = `[${killChainPhaseName}] ${obasAttackPattern.attack_pattern_name} - Email to the CISO`;

      console.time('[XTM]queryAi-obasAttackPattern-obasCreateInjectInScenario-ciso');
      await obasCreateInjectInScenario(
        obasScenario.scenario_id,
        'openbas_email',
        '2790bd39-37d4-4e39-be7e-53f3ca783f86',
        titleCiso,
        dependsOnDuration,
        { expectations: [], subject: responseCisoSubject.replace('Subject: ', '').replace('"', ''), body: responseCiso },
        [{ value: 'opencti', color: '#001bda' }, { value: 'ciso', color: '#b41313' }]
      );
      console.timeEnd('[XTM]queryAi-obasAttackPattern-obasCreateInjectInScenario-ciso');
      dependsOnDuration += (interval * 60);
    } else {
      console.time('[XTM]obasGetInjectorContracts');
      const obasInjectorContracts = await obasGetInjectorContracts(obasAttackPattern.attack_pattern_id);
      console.timeEnd('[XTM]obasGetInjectorContracts');
      let finalObasInjectorContracts = R.take(5, getShuffledArr(obasInjectorContracts));
      if (selection === 'random') {
        finalObasInjectorContracts = R.take(1, finalObasInjectorContracts);
      }
      if (simulationType === 'technical') {
        // eslint-disable-next-line no-restricted-syntax
        for (const finalObasInjectorContract of finalObasInjectorContracts) {
          const obasInjectorContractContent = JSON.parse(finalObasInjectorContract.injector_contract_content);
          const title = `[${obasAttackPattern.attack_pattern_external_id}] ${obasAttackPattern.attack_pattern_name} - ${finalObasInjectorContract.injector_contract_labels.en}`;
          console.time('[XTM]obasCreateInjectInScenario-tech');
          await obasCreateInjectInScenario(
            obasScenario.scenario_id,
            obasInjectorContractContent.config.type,
            finalObasInjectorContract.injector_contract_id,
            title,
            dependsOnDuration,
            null,
            [{ value: 'opencti', color: '#001bda' }, { value: 'technical', color: '#b9461a' }]
          );
          console.timeEnd('[XTM]obasCreateInjectInScenario-tech');
          dependsOnDuration += (interval * 60);
        }
      } else {
        // TODO
        logApp.info(`[XTM] simulationType ${simulationType} not implemented yet.`);
      }
    }
  } // end loop for
  const aiAttackPatterEmailEnd = new Date().getTime();
  console.timeEnd('[XTM]obasAttackPattern loop');
  logApp.info(`[XTM][TIME] AI generated ${sortedEnrichedFilteredObasAttackPatterns} attack pattern email in ${aiAttackPatterEmailEnd - aiAttackPatterEmailStart} ms.`);
  logApp.info(`[XTM][TIME] TOTAL everything processed and send to obas in ${aiAttackPatterEmailEnd - startingDate} ms`);
  console.timeEnd('[XTM]generateOpenBasScenario ALL');
  return `${XTM_OPENBAS_URL}/admin/scenarios/${obasScenario.scenario_id}/injects`;
};

export const generateContainerScenario = async (context, user, args) => {
  // ici
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
