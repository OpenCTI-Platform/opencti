import conf, { logApp } from '../config/conf';
import { type GetHttpClient, getHttpClient } from '../utils/http-client';
import type { Label } from '../generated/graphql';
import { DatabaseError } from '../config/errors';

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

export const createScenario = async (name: string, subtitle: string, description: string, tags: Label[]) => {
  const httpClient = buildXTmOpenBasHttpClient();
  try {
    const obasTagsIds = [];
    // eslint-disable-next-line no-restricted-syntax
    for (const tag of tags) {
      const { data: obasTag } = await httpClient.post('/tags/upsert', { tag_name: tag.value, tag_color: tag.color });
      obasTagsIds.push(obasTag.tag_id);
    }
    const { data: scenario } = await httpClient.post('/scenarios', { scenario_name: name, scenario_subtitle: subtitle, scenario_description: description, scenario_tags: obasTagsIds });
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
        inject_content: content
      }
    );
    return inject;
  } catch (err) {
    throw DatabaseError('Error querying OpenBAS', { cause: err });
  }
};

export const getResultsForAttackPatterns = async (attackPatternExternalIds: string[]) => {
  // TODO
  logApp.info(attackPatternExternalIds);
};
