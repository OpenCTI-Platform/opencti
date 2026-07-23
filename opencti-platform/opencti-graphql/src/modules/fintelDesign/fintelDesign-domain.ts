import type { AuthContext, AuthUser } from '../../types/user';
import { type EntityOptions, fullEntitiesList, pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import { type BasicStoreEntityFintelDesign, ENTITY_TYPE_FINTEL_DESIGN, type StoreEntityFintelDesign } from './fintelDesign-types';
import { type EditContext, type FintelDesignAddInput, FilterMode, FilterOperator, type MutationFintelDesignFieldPatchArgs } from '../../generated/graphql';
import { createEntity, deleteElementById, updateAttribute } from '../../database/middleware';
import { publishUserAction } from '../../listener/UserActionListener';
import { BUS_TOPICS } from '../../config/conf';
import { notify, setEditContext } from '../../database/redis';
import { FunctionalError, UnsupportedError } from '../../config/errors';
import { type FileUploadData, uploadToStorage } from '../../database/file-storage';
import { guessMimeType } from '../../database/file-storage';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { checkEnterpriseEdition } from '../../enterprise-edition/ee';
import { lockResources } from '../../lock/master-lock';

export const findById = async (context: AuthContext, user: AuthUser, id: string): Promise<BasicStoreEntityFintelDesign> => {
  await checkEnterpriseEdition(context);
  return storeLoadById(context, user, id, ENTITY_TYPE_FINTEL_DESIGN);
};

export const findFintelDesignPaginated = async (context: AuthContext, user: AuthUser, opts: EntityOptions<BasicStoreEntityFintelDesign>) => {
  await checkEnterpriseEdition(context);
  return pageEntitiesConnection<BasicStoreEntityFintelDesign>(context, user, [ENTITY_TYPE_FINTEL_DESIGN], opts);
};

export const addFintelDesign = async (context: AuthContext, user: AuthUser, fintelDesign: FintelDesignAddInput) => {
  await checkEnterpriseEdition(context);
  const shouldSetDefault = (fintelDesign as { default?: boolean }).default === true;

  // The default status is stored on the object itself (fintelDesign) rather than on a parent entity.
  // While this simplifies certain aspects of the design, it makes it hard to guarantee that only one default exists at a time.
  // Without a lock, two concurrent operations (e.g. one setting a new default while another is promoting an existing design)
  // could leave us with multiple defaults or none at all.
  // Locking prevents this race condition.
  // Note: a cleaner long-term approach would be to store the default reference as a dedicated field on a settings entity,
  // which would make this unicity constraint trivial to enforce.
  const lock = shouldSetDefault ? await lockResources(['fintel-design-default']) : null;
  try {
    const created = await createEntity(context, user, fintelDesign, ENTITY_TYPE_FINTEL_DESIGN);
    if (shouldSetDefault) {
      await applyUniqueDefaultFintelDesignConstraint(context, user, created.id);
    }
    await publishUserAction({
      user,
      event_type: 'mutation',
      event_scope: 'create',
      event_access: 'administration',
      message: `creates fintel design '${fintelDesign.name}`,
      context_data: {
        id: created.id,
        entity_type: ENTITY_TYPE_FINTEL_DESIGN,
        input: fintelDesign,
      },
    });
    return notify(BUS_TOPICS[ENTITY_TYPE_FINTEL_DESIGN].ADDED_TOPIC, created, user);
  } finally {
    if (lock) await lock.unlock();
  }
};

const applyUniqueDefaultFintelDesignConstraint = async (
  context: AuthContext,
  user: AuthUser,
  newDefaultDesignId: string,
): Promise<StoreEntityFintelDesign[]> => {
  const previousDefaultDesigns = await fullEntitiesList<BasicStoreEntityFintelDesign>(
    context,
    user,
    [ENTITY_TYPE_FINTEL_DESIGN],
    {
      baseData: true,
      filters: {
        filters: [{
          key: ['default'],
          values: ['true'],
        }, {
          key: ['id'],
          values: [newDefaultDesignId],
          operator: FilterOperator.NotEq,
        }],
        filterGroups: [],
        mode: FilterMode.And,
      },
    },
  );

  if (previousDefaultDesigns.length === 0) {
    return [];
  }

  const results = await Promise.all(
    previousDefaultDesigns.map((entity) => updateAttribute<StoreEntityFintelDesign>(
      context,
      user,
      entity.id,
      ENTITY_TYPE_FINTEL_DESIGN,
      [{
        key: 'default',
        value: ['false'],
      }],
    )),
  );

  return results.map(({ element }) => element);
};

const isEditInputSetAsDefault = (input: MutationFintelDesignFieldPatchArgs['input']) => {
  const defaultInput = input?.find((i) => i.key === 'default');
  const firstValue = defaultInput?.value?.[0];
  if (typeof firstValue === 'boolean') {
    return firstValue;
  }
  if (typeof firstValue === 'string') {
    return firstValue === 'true';
  }
  return false;
};

const uploadFintelDesignFile = async (context: AuthContext, user: AuthUser, fintelDesignId: string, file: FileUploadData) => {
  const fullFile = await file;
  const mimeType = guessMimeType(fullFile.filename);
  if (!mimeType.includes('image/')) {
    throw UnsupportedError('Fintel design logo file format must be image/', { mimeType });
  }
  const fintelDesignLogoFile = { ...fullFile, filename: `${fintelDesignId}` };
  const { upload } = await uploadToStorage(context, user, 'fintelDesigns', fintelDesignLogoFile, {});
  return { upload };
};

export const fintelDesignEditField = async (
  context: AuthContext,
  user: AuthUser,
  args: MutationFintelDesignFieldPatchArgs,
) => {
  await checkEnterpriseEdition(context);
  const { id, file, input } = args;
  const fintelDesign = await findById(context, user, id);
  if (!fintelDesign) {
    throw FunctionalError(`Fintel design ${id} cannot be found`);
  }
  let fileId;
  if (file) {
    const { upload } = await uploadFintelDesignFile(context, user, fintelDesign.internal_id, file);
    fileId = upload.id;
  }

  const finalInput = [...(input ?? []), ...(fileId ? [{ key: 'file_id', value: [fileId] }] : [])];
  if (finalInput.length === 0) {
    return null;
  }

  const settingDefault = isEditInputSetAsDefault(finalInput);

  // The default status is stored on the object itself (fintelDesign) rather than on a parent entity.
  // While this simplifies certain aspects of the design, it makes it hard to guarantee that only one default exists at a time.
  // Without a lock, two concurrent operations (e.g. one setting a new default while another is promoting an existing design)
  // could leave us with multiple defaults or none at all.
  // Locking prevents this race condition.
  // Note: a cleaner long-term approach would be to store the default reference as a dedicated field on a settings entity,
  // which would make this unicity constraint trivial to enforce.
  const lock = settingDefault ? await lockResources(['fintel-design-default']) : null;
  try {
    const { element } = await updateAttribute<StoreEntityFintelDesign>(context, user, id, ENTITY_TYPE_FINTEL_DESIGN, finalInput);
    if (settingDefault) {
      await applyUniqueDefaultFintelDesignConstraint(context, user, element.id);
    }
    await publishUserAction({
      user,
      event_type: 'mutation',
      event_scope: 'update',
      event_access: 'administration',
      message: `updates ${(input ?? []).map((i) => i.key).join(', ')} for fintel design ${element.name}`,
      context_data: {
        id: element.id,
        entity_type: ENTITY_TYPE_FINTEL_DESIGN,
        input,
      },
    });
    return notify(BUS_TOPICS[ENTITY_TYPE_FINTEL_DESIGN].EDIT_TOPIC, element, user);
  } finally {
    if (lock) await lock.unlock();
  }
};

export const fintelDesignDelete = async (context: AuthContext, user: AuthUser, designId: string) => {
  await checkEnterpriseEdition(context);
  const deleted = await deleteElementById<StoreEntityFintelDesign>(
    context,
    user,
    designId,
    ENTITY_TYPE_FINTEL_DESIGN,
  );

  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'delete',
    event_access: 'administration',
    message: `deletes fintel design \`${deleted.name}\``,
    context_data: {
      id: deleted.id,
      entity_type: ENTITY_TYPE_FINTEL_DESIGN,
      input: deleted,
    },
  });

  return notify(BUS_TOPICS[ENTITY_TYPE_FINTEL_DESIGN].DELETE_TOPIC, deleted, user).then(() => designId);
};

export const fintelDesignEditContext = async (context: AuthContext, user: AuthUser, fintelDesignId: string, input?: EditContext) => {
  await checkEnterpriseEdition(context);
  if (input) {
    await setEditContext(user, fintelDesignId, input);
  }
  return storeLoadById(context, user, fintelDesignId, ABSTRACT_INTERNAL_OBJECT).then((fintelDesign) => {
    return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].CONTEXT_TOPIC, fintelDesign, user);
  });
};
