import * as Yup from 'yup';

const decayRuleValidator = (t: (value: string) => string) => Yup.object().shape({
  name: Yup.string().min(2).required(t('This field is required')),
  description: Yup.string().nullable(),
  active: Yup.boolean(),
  order: Yup.number()
    .min(1, t('The value must be greater than or equal to 1'))
    .max(100000, t('The value is too long')),
  decay_lifetime: Yup.number()
    .min(1, t('The value must be greater than or equal to 1'))
    .max(100000, t('The value is too long')),
  decay_pound: Yup.number()
    .min(0, t('The value must be greater than or equal to 0'))
    .max(100000, t('The value is too long')),
  decay_revoke_score: Yup.number()
    .min(0, t('The value must be greater than or equal to 0'))
    .max(100, t('The value must be less than or equal to 100')),
  decay_observable_types: Yup.array().of(Yup.string()),
  decay_points: Yup.array().of(Yup.number()
    .min(0, t('The value must be greater than or equal to 0'))
    .max(100, t('The value must be less than or equal to 100'))),
});
export default decayRuleValidator;
