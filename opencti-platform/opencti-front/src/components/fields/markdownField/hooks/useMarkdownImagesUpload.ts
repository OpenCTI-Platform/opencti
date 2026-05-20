import { graphql } from 'react-relay';
import { commitMutation } from '../../../../relay/environment';
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
        name
      }
    }
  }
`;

const encodePathSegments = (path: string): string => {
  return path
    .split('/')
    .filter((segment) => segment.length > 0)
    .map((segment) => encodeURIComponent(segment))
    .join('/');
};

const toEmbeddedMarkdownUrl = (uploadedFileId: string, uploadedFileName: string): string => {
  if (uploadedFileName) {
    return `embedded/${encodePathSegments(uploadedFileName)}`;
  }

  const normalizedId = uploadedFileId.startsWith('/') ? uploadedFileId.slice(1) : uploadedFileId;
  const filename = normalizedId.split('/').pop();
  if (!filename) {
    throw new Error('Missing uploaded file name');
  }
  return `embedded/${encodePathSegments(filename)}`;
};

const useMarkdownImagesUpload = ({
  uploadEntityId,
  uploadFileMarkings = [],
}: UseMarkdownImagesUploadArgs) => {
  const uploadFile = (file: File, uploadEntityIdOverride?: string): Promise<{ id: string; name: string }> => {
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
            importPush?: { id?: string; name?: string } | null;
          } | null;
        }) => {
          const uploadedFile = response?.stixCoreObjectEdit?.importPush;
          if (!uploadedFile?.id) {
            reject(new Error('Missing uploaded file id'));
            return;
          }
          resolve({ id: uploadedFile.id, name: uploadedFile.name ?? '' });
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

      const uploadedFile = await uploadFile(attachment.file, options?.uploadEntityIdOverride);
      const finalUrl = toEmbeddedMarkdownUrl(uploadedFile.id, uploadedFile.name);
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
