import type { AuthContext, AuthUser } from '../../types/user';
import { type EntityOptions, pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import { type BasicStoreEntityFintelDesign, ENTITY_TYPE_FINTEL_DESIGN } from './fintelDesign-types';
import type { EditContext, FintelDesignAddInput, MutationFintelDesignFieldPatchArgs } from '../../generated/graphql';
import { createEntity, deleteElementById, updateAttribute } from '../../database/middleware';
import { publishUserAction } from '../../listener/UserActionListener';
import { BUS_TOPICS } from '../../config/conf';
import { notify, setEditContext } from '../../database/redis';
import { FunctionalError, UnsupportedError } from '../../config/errors';
import { type FileUploadData, uploadToStorage } from '../../database/file-storage';
import { guessMimeType } from '../../database/file-storage';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { checkEnterpriseEdition } from '../../enterprise-edition/ee';

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
  const created = await createEntity(context, user, fintelDesign, ENTITY_TYPE_FINTEL_DESIGN);
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
  const { element } = await updateAttribute(context, user, id, ENTITY_TYPE_FINTEL_DESIGN, finalInput);
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
    }
  });
  return notify(BUS_TOPICS[ENTITY_TYPE_FINTEL_DESIGN].EDIT_TOPIC, element, user);
};

export const fintelDesignDelete = async (context: AuthContext, user: AuthUser, designId: string) => {
  await checkEnterpriseEdition(context);
  const deleted = await deleteElementById(
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
