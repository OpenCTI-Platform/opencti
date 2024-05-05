import conf, { logApp } from '../config/conf';
import { type GetHttpClient, getHttpClient } from '../utils/http-client';
import type { Label } from '../generated/graphql';
import { DatabaseError } from '../config/errors';
import { utcDate } from '../utils/format';
import { isEmptyField } from './utils';

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

export const createScenario = async (name: string, subtitle: string, description: string, tags: Label[], id: string, category: string) => {
  const httpClient = buildXTmOpenBasHttpClient();
  try {
    const obasTagsIds = [];
    // eslint-disable-next-line no-restricted-syntax
    for (const tag of tags) {
      const { data: obasTag } = await httpClient.post('/tags/upsert', { tag_name: tag.value, tag_color: tag.color });
      obasTagsIds.push(obasTag.tag_id);
    }
    const { data: scenario } = await httpClient.post('/scenarios', {
      scenario_name: name,
      scenario_subtitle: subtitle,
      scenario_description: description,
      scenario_tags: obasTagsIds,
      scenario_external_reference: id,
      scenario_category: category,
      scenario_main_focus: 'incident-response',
      scenario_severity: 'high',
    });
    return scenario;
  } catch (err) {
    throw DatabaseError('Error querying OpenBAS', { cause: err });
  }
};

export const createInjectInScenario = async (scenarioId: string, injectorType: string, contractId: string, title: string, dependsDuration: number, content: string | null) => {
  const httpClient = buildXTmOpenBasHttpClient();
  try {
    const { data: inject } = await httpClient.post(
      `/scenarios/${scenarioId}/injects`,
      {
        inject_injector_contract: contractId,
        inject_type: injectorType,
        inject_title: title,
        inject_depends_duration: dependsDuration,
        inject_content: content,
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
    const { data: scenario } = await httpClient.get(`/scenarios/external_reference/${id}`);
    if (!scenario || !scenario.scenario_id) {
      return noResult;
    }
    const { data: exercises } = await httpClient.get(`/scenarios/${scenario.scenario_id}/exercises`);
    if (exercises.length === 0) {
      return noResult;
    }
    const sortedExercises = exercises.sort(
      (a: { exercise_start_date: string; }, b: { exercise_start_date: string; }) => utcDate(b.exercise_start_date).diff(utcDate(a.exercise_start_date))
    );
    const latestExercise = sortedExercises.at(0);
    const prevention = latestExercise.exercise_global_score.filter((n: { type: string, value: number }) => n.type === 'PREVENTION').at(0);
    const preventionResult = prevention.avgResult === 'UNKNOWN' ? {
      unknown: 1,
      success: 0,
      failure: 0
    } : {
      unknown: prevention.distribution?.filter((n: { label: string, value: number }) => n.label === 'Pending').at(0).value,
      success: prevention.distribution?.filter((n: { label: string, value: number }) => n.label === 'Successful').at(0).value,
      failure: prevention.distribution?.filter((n: { label: string, value: number }) => n.label === 'Failed').at(0).value
    };
    const detection = latestExercise.exercise_global_score.filter((n: { type: string, value: number }) => n.type === 'DETECTION').at(0);
    const detectionResult = detection.avgResult === 'UNKNOWN' ? {
      unknown: 1,
      success: 0,
      failure: 0
    } : {
      unknown: detection.distribution?.filter((n: { label: string, value: number }) => n.label === 'Pending').at(0).value,
      success: detection.distribution?.filter((n: { label: string, value: number }) => n.label === 'Successful').at(0).value,
      failure: detection.distribution?.filter((n: { label: string, value: number }) => n.label === 'Failed').at(0).value
    };
    const humanResponse = latestExercise.exercise_global_score.filter((n: { type: string, value: number }) => n.type === 'HUMAN_RESPONSE').at(0);
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
