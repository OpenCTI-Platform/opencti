import conf, { getBaseUrl, logApp } from '../config/conf';
import { type GetHttpClient, getHttpClient } from '../utils/http-client';
import type { Label } from '../generated/graphql';
import { DatabaseError } from '../config/errors';
import { isEmptyField } from './utils';
import { ENTITY_TYPE_CAMPAIGN, ENTITY_TYPE_CONTAINER_REPORT, ENTITY_TYPE_INCIDENT, ENTITY_TYPE_INTRUSION_SET, ENTITY_TYPE_THREAT_ACTOR_GROUP } from '../schema/stixDomainObject';
import { ENTITY_TYPE_CONTAINER_CASE_INCIDENT } from '../modules/case/case-incident/case-incident-types';
import { ENTITY_TYPE_CONTAINER_GROUPING } from '../modules/grouping/grouping-types';
import { ENTITY_TYPE_CONTAINER_CASE_RFI } from '../modules/case/case-rfi/case-rfi-types';
import { ENTITY_TYPE_CONTAINER_CASE_RFT } from '../modules/case/case-rft/case-rft-types';
import { ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL } from '../modules/threatActorIndividual/threatActorIndividual-types';

const XTM_OPENBAS_URL = conf.get('xtm:openbas_url');
const XTM_OPENBAS_TOKEN = conf.get('xtm:openbas_token');
const XTM_OPENBAS_REJECT_UNAUTHORIZED = conf.get('xtm:openbas_reject_unauthorized');

export const buildXTmOpenBasHttpClient = () => {
  const httpClientOptions: GetHttpClient = {
    baseURL: `${XTM_OPENBAS_URL}/api`,
    responseType: 'json',
    rejectUnauthorized: XTM_OPENBAS_REJECT_UNAUTHORIZED,
    headers: {
      Authorization: `Bearer ${XTM_OPENBAS_TOKEN}`
    }
  };
  return getHttpClient(httpClientOptions);
};

export const getKillChainPhases = async () => {
  const httpClient = buildXTmOpenBasHttpClient();
  try {
    const { data: killChainPhases } = await httpClient.get('/kill_chain_phases');
    return killChainPhases;
  } catch (err) {
    throw DatabaseError('Error querying OpenBAS', { cause: err });
  }
};

export const getAttackPatterns = async () => {
  const httpClient = buildXTmOpenBasHttpClient();
  try {
    const { data: attackPatterns } = await httpClient.get('/attack_patterns');
    return attackPatterns;
  } catch (err) {
    throw DatabaseError('Error querying OpenBAS', { cause: err });
  }
};

export const getInjectorContracts = async (attackPatternId: string) => {
  const httpClient = buildXTmOpenBasHttpClient();
  try {
    const { data: injectorContracts } = await httpClient.get(`/attack_patterns/${attackPatternId}/injector_contracts`);
    return injectorContracts;
  } catch (err) {
    throw DatabaseError('Error querying OpenBAS', { cause: err });
  }
};

export const createScenario = async (name: string, subtitle: string, description: string, tags: Label[], id: string, type: string, category: string) => {
  const httpClient = buildXTmOpenBasHttpClient();
  try {
    const obasTagsIds = [];
    // eslint-disable-next-line no-restricted-syntax
    for (const tag of tags) {
      const { data: obasTag } = await httpClient.post('/tags/upsert', { tag_name: tag.value, tag_color: tag.color });
      obasTagsIds.push(obasTag.tag_id);
    }
    let uri;
    switch (type) {
      case ENTITY_TYPE_CONTAINER_REPORT:
        uri = 'analyses/reports';
        break;
      case ENTITY_TYPE_CONTAINER_GROUPING:
        uri = 'analyses/groupings';
        break;
      case ENTITY_TYPE_CONTAINER_CASE_INCIDENT:
        uri = 'cases/incidents';
        break;
      case ENTITY_TYPE_CONTAINER_CASE_RFI:
        uri = 'cases/rfis';
        break;
      case ENTITY_TYPE_CONTAINER_CASE_RFT:
        uri = 'cases/rfts';
        break;
      case ENTITY_TYPE_INCIDENT:
        uri = 'events/incidents';
        break;
      case ENTITY_TYPE_CAMPAIGN:
        uri = 'threats/campaigns';
        break;
      case ENTITY_TYPE_INTRUSION_SET:
        uri = 'threats/intrusion_sets';
        break;
      case ENTITY_TYPE_THREAT_ACTOR_GROUP:
        uri = 'threats/threat_actors_group';
        break;
      case ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL:
        uri = 'threats/threat_actors_individual';
        break;
      default:
        uri = null;
    }
    const { data: scenario } = await httpClient.post('/scenarios', {
      scenario_name: name,
      scenario_subtitle: subtitle,
      scenario_description: description,
      scenario_tags: obasTagsIds,
      scenario_external_reference: id,
      scenario_external_url: uri ? `${getBaseUrl()}/dashboard/${uri}/${id}` : null,
      scenario_category: category,
      scenario_main_focus: 'incident-response',
      scenario_severity: 'high',
    });
    return scenario;
  } catch (err) {
    throw DatabaseError('Error querying OpenBAS', { cause: err });
  }
};

export const createInjectInScenario = async (
  scenarioId: string,
  injectorType: string,
  contractId: string,
  title: string,
  dependsDuration: number,
  content: string | null,
  tags: Label[]
) => {
  const httpClient = buildXTmOpenBasHttpClient();
  try {
    const obasTagsIds = [];
    // eslint-disable-next-line no-restricted-syntax
    for (const tag of tags) {
      const { data: obasTag } = await httpClient.post('/tags/upsert', { tag_name: tag.value, tag_color: tag.color });
      obasTagsIds.push(obasTag.tag_id);
    }
    const { data: inject } = await httpClient.post(
      `/scenarios/${scenarioId}/injects`,
      {
        inject_injector_contract: contractId,
        inject_type: injectorType,
        inject_title: title.length > 255 ? `${title.substring(0, 250)}...` : title,
        inject_depends_duration: dependsDuration,
        inject_content: content,
        inject_tags: obasTagsIds,
      }
    );
    return inject;
  } catch (err) {
    throw DatabaseError('Error querying OpenBAS', { cause: err });
  }
};

export const getScenarioResult = async (id: string) => {
  const noResult = {
    prevention: {
      unknown: 1,
      success: 0,
      failure: 0,
    },
    detection: {
      unknown: 1,
      success: 0,
      failure: 0,
    },
    human: {
      unknown: 1,
      success: 0,
      failure: 0,
    }
  };
  // OpenBAS not configured
  if (isEmptyField(XTM_OPENBAS_URL) || isEmptyField(XTM_OPENBAS_TOKEN)) {
    return noResult;
  }
  const httpClient = buildXTmOpenBasHttpClient();
  try {
    const { data: exercise } = await httpClient.get(`/opencti/v1/exercises/latest/${id}`);
    if (!exercise || !exercise.exercise_id) {
      return noResult;
    }
    const prevention = exercise.exercise_global_score.filter((n: { type: string, value: number }) => n.type === 'PREVENTION').at(0);
    const preventionResult = prevention.avgResult === 'UNKNOWN' ? {
      unknown: 1,
      success: 0,
      failure: 0
    } : {
      unknown: prevention.distribution?.filter((n: { label: string, value: number }) => n.label === 'Pending').at(0).value,
      success: prevention.distribution?.filter((n: { label: string, value: number }) => n.label === 'Successful').at(0).value,
      failure: prevention.distribution?.filter((n: { label: string, value: number }) => n.label === 'Failed').at(0).value
    };
    const detection = exercise.exercise_global_score.filter((n: { type: string, value: number }) => n.type === 'DETECTION').at(0);
    const detectionResult = detection.avgResult === 'UNKNOWN' ? {
      unknown: 1,
      success: 0,
      failure: 0
    } : {
      unknown: detection.distribution?.filter((n: { label: string, value: number }) => n.label === 'Pending').at(0).value,
      success: detection.distribution?.filter((n: { label: string, value: number }) => n.label === 'Successful').at(0).value,
      failure: detection.distribution?.filter((n: { label: string, value: number }) => n.label === 'Failed').at(0).value
    };
    const humanResponse = exercise.exercise_global_score.filter((n: { type: string, value: number }) => n.type === 'HUMAN_RESPONSE').at(0);
    const humanResponseResult = humanResponse.avgResult === 'UNKNOWN' ? {
      unknown: 1,
      success: 0,
      failure: 0
    } : {
      unknown: humanResponse.distribution?.filter((n: { label: string, value: number }) => n.label === 'Pending').at(0).value,
      success: humanResponse.distribution?.filter((n: { label: string, value: number }) => n.label === 'Successful').at(0).value,
      failure: humanResponse.distribution?.filter((n: { label: string, value: number }) => n.label === 'Failed').at(0).value
    };
    return {
      prevention: preventionResult,
      detection: detectionResult,
      human: humanResponseResult
    };
  } catch (err) {
    logApp.info('Scenario not found in OpenBAS', { err });
    return noResult;
  }
};
