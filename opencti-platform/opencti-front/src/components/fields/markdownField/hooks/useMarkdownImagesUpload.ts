import { graphql } from 'react-relay';
import { commitMutation } from '../../../../relay/environment';
import { getFileUri } from '../../../../utils/utils';
import { extractTempImageTokens, MarkdownTempAttachmentRegistry, replaceTempImageTokenUrl } from '../core/markdownImagePreviewUtils';

type UseMarkdownImagesUploadArgs = {
  uploadEntityId?: string;
  uploadFileMarkings?: string[];
};

const uploadEntityImportPushMutation = graphql`
  mutation useMarkdownImagesUploadMutation(
    $id: ID!
    $file: Upload!
    $fileMarkings: [String]
    $noTriggerImport: Boolean
    $fromTemplate: Boolean
    $embedded: Boolean
  ) {
    stixCoreObjectEdit(id: $id) {
      importPush(
        file: $file
        fileMarkings: $fileMarkings
        noTriggerImport: $noTriggerImport
        fromTemplate: $fromTemplate
        embedded: $embedded
      ) {
        id
      }
    }
  }
`;

const extensionByMimeType: Record<string, string> = {
  'image/png': 'png',
  'image/jpeg': 'jpg',
  'image/jpg': 'jpg',
  'image/gif': 'gif',
  'image/webp': 'webp',
};

const withUniqueUploadName = (file: File, token: string): File => {
  const trimmedName = file.name.trim();
  const lastDotIndex = trimmedName.lastIndexOf('.');
  const hasExtension = lastDotIndex > 0 && lastDotIndex < trimmedName.length - 1;

  const currentBaseName = hasExtension ? trimmedName.slice(0, lastDotIndex) : trimmedName;
  const currentExtension = hasExtension ? trimmedName.slice(lastDotIndex + 1) : '';
  const fallbackExtension = extensionByMimeType[file.type] ?? '';

  const baseName = currentBaseName || 'image';
  const extension = currentExtension || fallbackExtension;
  const tokenSuffix = token.slice(0, 8);
  const uniqueName = extension
    ? `${baseName}-${tokenSuffix}.${extension}`
    : `${baseName}-${tokenSuffix}`;

  return new File([file], uniqueName, {
    type: file.type,
    lastModified: file.lastModified,
  });
};

const useMarkdownImagesUpload = ({
  uploadEntityId,
  uploadFileMarkings = [],
}: UseMarkdownImagesUploadArgs) => {
  const uploadFile = (file: File, uploadEntityIdOverride?: string): Promise<string> => {
    return new Promise((resolve, reject) => {
      const resolvedUploadEntityId = uploadEntityIdOverride ?? uploadEntityId;
      if (!resolvedUploadEntityId) {
        reject(new Error('Missing upload entity id'));
        return;
      }

      const variables = {
        id: resolvedUploadEntityId,
        file,
        fileMarkings: uploadFileMarkings,
        noTriggerImport: false,
        fromTemplate: false,
        embedded: true,
      };

      commitMutation({
        mutation: uploadEntityImportPushMutation,
        variables,
        updater: undefined,
        optimisticUpdater: undefined,
        optimisticResponse: undefined,
        onCompleted: (response: {
          stixCoreObjectEdit?: {
            importPush?: { id?: string } | null;
          } | null;
        }) => {
          const fileId = response?.stixCoreObjectEdit?.importPush?.id;
          if (!fileId) {
            reject(new Error('Missing uploaded file id'));
            return;
          }
          resolve(fileId);
        },
        onError: reject,
        setSubmitting: undefined,
      });
    });
  };

  const finalizeTempImageUrls = async (
    markdown: string,
    registry: MarkdownTempAttachmentRegistry,
    onTokenFinalized: (token: string) => void,
    options?: { uploadEntityIdOverride?: string },
  ): Promise<string> => {
    const tokens = extractTempImageTokens(markdown);
    if (tokens.length === 0) {
      return markdown;
    }

    let result = markdown;
    for (let i = 0; i < tokens.length; i += 1) {
      const token = tokens[i];
      const attachment = registry.getAttachment(token);
      if (!attachment) {
        continue;
      }

      const uploadFileInput = withUniqueUploadName(attachment.file, token);
      const fileId = await uploadFile(uploadFileInput, options?.uploadEntityIdOverride);
      const finalUrl = getFileUri(fileId);
      result = replaceTempImageTokenUrl(result, token, finalUrl);
      onTokenFinalized(token);
    }

    return result;
  };

  return {
    finalizeTempImageUrls,
  };
};

export default useMarkdownImagesUpload;
