import * as Yup from 'yup';

const decayRuleValidator = (t: (value: string) => string) => Yup.object().shape({
  name: Yup.string().min(2).required(t('This field is required')),
  description: Yup.string().nullable(),
  active: Yup.boolean(),
  order: Yup.number().min(1).max(Number.MAX_SAFE_INTEGER),
  decay_lifetime: Yup.number().min(1).max(Number.MAX_SAFE_INTEGER),
  decay_pound: Yup.number().min(0).max(Number.MAX_SAFE_INTEGER),
  decay_revoke_score: Yup.number().min(0).max(Number.MAX_SAFE_INTEGER),
  decay_observable_types: Yup.array().of(Yup.string()),
  decay_points: Yup.array().of(Yup.number().min(0).max(Number.MAX_SAFE_INTEGER)),
});
export default decayRuleValidator;
