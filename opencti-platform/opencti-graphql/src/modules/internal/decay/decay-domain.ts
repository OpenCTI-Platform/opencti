// --- Base score computing of the indicator => initialAmount for decay
// 100 - if source of indicator confidence is A, 50 if not.
// associated numeric value to vocabularies to use a weight

// --- Decay speed depending on a decay model.
// Decay model must be associated to indicators depending on condition? main_observable_type?

import type { AuthContext } from '../../../types/user';
import { convertStoreToStix } from '../../../database/stix-converter';
import { SYSTEM_USER } from '../../../utils/access';
import { utcDate } from '../../../utils/format';
import type { BasicStoreBase } from '../../../types/store';

export interface BasicStoreIndicator extends BasicStoreBase {
  entity_type: 'Indicator'
  base_type: 'ENTITY'
  name: string
  x_opencti_score: number,
  description: string
  indicator_types: string[]
  pattern: string
  pattern_type: string
  valid_from: Date
  valid_until: Date
}

interface DecayPound {
  decay_pound_filters: string
  decay_pound_factor: number
}
export interface DecayModel {
  id: string
  decay_lifetime: number
  decay_factor: number
  decay_pounds: DecayPound[]
  decay_points: number[]
  decay_revoked_cutoff: number
}
interface IndicatorDecayStep {
  decay_step_score: number
  decay_step_at: string
  decay_step_revoked: boolean
}
interface IndicatorDecay {
  decay_model_id: string
  decay_base_score: number
  decay_model_steps: IndicatorDecayStep[]
}

// export const DEFAULT_INDICATOR_TTL = 365;
// const INDICATOR_TTL_DEFINITION: Array<TTL_DEFINITION> = [
//   {
//     target: ['IPv4-Addr', 'IPv6-Addr'],
//     definition: {
//       [MARKING_TLP_CLEAR]: 30,
//       [MARKING_TLP_GREEN]: 30,
//       [MARKING_TLP_AMBER]: 30,
//       [MARKING_TLP_AMBER_STRICT]: 60,
//       [MARKING_TLP_RED]: 60,
//     },
//     default: 60
//   },
//   {
//     target: ['File'],
//     default: DEFAULT_INDICATOR_TTL
//   },
//   {
//     target: ['Url'],
//     definition: {
//       [MARKING_TLP_CLEAR]: 60,
//       [MARKING_TLP_GREEN]: 60,
//       [MARKING_TLP_AMBER]: 180,
//       [MARKING_TLP_AMBER_STRICT]: 180,
//       [MARKING_TLP_RED]: 180,
//     },
//     default: 180
//   },
// ];

// TODO think about application models. Apply on indicator filtering?
// What about the current situation where TTL is based on marking definitions
const DEFAULT_DECAY_MODEL: DecayModel = {
  id: 'DEFAULT_DECAY_MODEL',
  decay_lifetime: 30, // 30 days
  decay_factor: 3.0,
  decay_pounds: [], // No specific pounds
  decay_points: [60, 40], // 2 decay points
  decay_revoked_cutoff: 40,
  // decay_apply_on: // filters
};

export const computeScoreFromExpectedTime = (initialAmount: number, after: number, model: DecayModel, pound: number = 1) => {
  // Polynomial implementation (MISP approach)
  if (after > model.decay_lifetime) return 0;
  if (after <= 0) return initialAmount;
  return initialAmount * (1 - ((after / model.decay_lifetime) ** (1 / (model.decay_factor * pound))));
};

export const computeTimeFromExpectedScore = (initialAmount: number, score: number, model: DecayModel, pound: number = 1) => {
  // Polynomial implementation (MISP approach)
  return (Math.E ** (Math.log(1 - (score / initialAmount)) * (model.decay_factor * pound))) * model.decay_lifetime;
};

export const computeIndicatorPound = async (context: AuthContext, indicator: BasicStoreIndicator, decayPounds: DecayPound[]): Promise<number> => {
  let poundFactor = 1;
  //  const stixIndicator = convertStoreToStix(indicator);
  for (let index = 0; index < decayPounds.length; index += 1) {
    const { decay_pound_factor } = decayPounds[index];
    // const filters = JSON.parse(decay_pound_filters ?? '{}');
    // const adaptedFilters = await convertFiltersFrontendFormat(context, SYSTEM_USER, filters);
    // If match filter, apply decay_pound.
    // const isMatch = await isStixMatchFilters(context, SYSTEM_USER, stixIndicator, adaptedFilters);
    // if (isMatch) {
    poundFactor *= decay_pound_factor;
    // }
  }
  return poundFactor;
};

// eslint-disable-next-line @typescript-eslint/no-unused-vars
export const computeDecayModel = async (context: AuthContext, indicator: BasicStoreIndicator): Promise<DecayModel | undefined> => {
  // TODO Add models management
  // 01 - List existing decay models
  // 02 - Get the model that firstly match the set of model filters
  return DEFAULT_DECAY_MODEL;
};

export const computeIndicatorDecayWithModel = async (context: AuthContext, indicator: BasicStoreIndicator, model: DecayModel): Promise<IndicatorDecay> => {
  const computedSteps: IndicatorDecayStep[] = [];
  const { decay_points, decay_revoked_cutoff } = model;
  for (let index = 0; index < decay_points.sort().reverse().length; index += 1) {
    const point = decay_points[index];
    const computedPound = await computeIndicatorPound(context, indicator, model.decay_pounds);
    const expectedTime = computeTimeFromExpectedScore(indicator.x_opencti_score, point, model, computedPound);
    const nextStep = utcDate(indicator.valid_from).clone().add(expectedTime * 24, 'hours'); // Add with hours for more precision
    computedSteps.push({
      decay_step_score: point,
      decay_step_at: nextStep.toISOString(),
      decay_step_revoked: decay_revoked_cutoff >= point
    });
  }
  return {
    decay_model_id: model.id,
    decay_base_score: indicator.x_opencti_score,
    decay_model_steps: computedSteps
  };
};

export const computeIndicatorDecay = async (context: AuthContext, indicator: BasicStoreIndicator): Promise<IndicatorDecay | undefined> => {
  const model = await computeDecayModel(context, indicator);
  return model ? computeIndicatorDecayWithModel(context, indicator, model) : undefined;
};

export const computeIndicatorBaseScore = async (indicator: BasicStoreIndicator): Promise<number> => {
  // TODO Add specific behavior
  return indicator.x_opencti_score ?? 50;
};
