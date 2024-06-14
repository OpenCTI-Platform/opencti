import { storeLoadByIdWithRefs } from '../../../database/middleware';
import { INPUT_CREATED_BY, INPUT_GRANTED_REFS, INPUT_LABELS, INPUT_MARKINGS } from '../../../schema/general';
import { controlUserConfidenceAgainstElement } from '../../../utils/confidence-level';
import { createIndicatorFromObservable } from '../../../domain/stixCyberObservable';

// region [>=6.2 & <6.5]
/**
 * @deprecated [>=6.2 & <6.5]. Use `promoteToIndicator`.
 */
export const promoteObservableToIndicator = async (context, user, observableId) => {
  const observable = await storeLoadByIdWithRefs(context, user, observableId);
  controlUserConfidenceAgainstElement(user, observable);
  const objectLabel = (observable[INPUT_LABELS] ?? []).map((n) => n.internal_id);
  const objectMarking = (observable[INPUT_MARKINGS] ?? []).map((n) => n.internal_id);
  const objectOrganization = (observable[INPUT_GRANTED_REFS] ?? []).map((n) => n.internal_id);
  const createdBy = observable[INPUT_CREATED_BY]?.internal_id;
  await createIndicatorFromObservable(context, user, { objectLabel, objectMarking, objectOrganization, createdBy }, observable);
  return observable;
};
// endregion
