import { RefObject, useCallback, useEffect, useRef } from 'react';
import { cleanupRemovedTempAttachments, extractEmbeddedStoragePathsFromMarkdown } from '../core/markdownImageFieldHelpers';
import { extractTempImageTokens, MarkdownTempAttachmentRegistry } from '../core/markdownImagePreviewUtils';
import type { MarkdownImagesController, MarkdownImagesTab } from '../core/markdownImagesController';
import useMarkdownImageInteractions from './useMarkdownImageInteractions';
import useMarkdownImagesUpload from './useMarkdownImagesUpload';

type UseMarkdownImagesArgs = {
  activeTab: MarkdownImagesTab;
  disabled?: boolean;
  isImageUploadEnabled: boolean;
  t_i18n: (value: string) => string;
  containerRef: RefObject<HTMLDivElement | null>;
  value: string;
  onValueChange: (nextValue: string, shouldValidate?: boolean) => void;
  setDraftValue: (nextValue: string) => void;
  pushDraftValue: (nextValue: string, shouldValidate?: boolean) => void;
  isFieldFocusedRef: RefObject<boolean>;
  registerMarkdownImagesController?: (controller: MarkdownImagesController) => void;
  uploadEntityId?: string;
  uploadFileMarkings?: string[];
  tempCleanupDelayMs: number;
  maxImageSizeBytes: number;
};

const useMarkdownImages = ({
  activeTab,
  disabled,
  isImageUploadEnabled,
  t_i18n,
  containerRef,
  value,
  onValueChange,
  setDraftValue,
  pushDraftValue,
  isFieldFocusedRef,
  registerMarkdownImagesController,
  uploadEntityId,
  uploadFileMarkings = [],
  tempCleanupDelayMs,
  maxImageSizeBytes,
}: UseMarkdownImagesArgs) => {
  const { finalizeTempImageUrls } = useMarkdownImagesUpload({
    uploadEntityId,
    uploadFileMarkings,
  });

  const pendingCleanupTimeoutRef = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map());
  const latestMarkdownRef = useRef(value ?? '');
  const submittedEmbeddedPathsRef = useRef(new Set(extractEmbeddedStoragePathsFromMarkdown(value ?? '')));
  const registryRef = useRef(new MarkdownTempAttachmentRegistry());

  const syncLatestMarkdown = useCallback((nextValue: string) => {
    latestMarkdownRef.current = nextValue;
  }, []);

  const pushDraftAndSyncLatest = useCallback((nextValue: string, shouldValidate = false) => {
    syncLatestMarkdown(nextValue);
    pushDraftValue(nextValue, shouldValidate);
  }, [pushDraftValue, syncLatestMarkdown]);

  const syncFromExternalValue = useCallback((nextValue: string) => {
    latestMarkdownRef.current = nextValue;
    setDraftValue(nextValue);
    submittedEmbeddedPathsRef.current = new Set(extractEmbeddedStoragePathsFromMarkdown(nextValue));
  }, [setDraftValue]);

  const removeFinalizedToken = useCallback((token: string) => {
    pendingCleanupTimeoutRef.current.delete(token);
    registryRef.current.removeTempAttachment(token);
  }, []);

  const applyFinalizedMarkdown = useCallback((originalMarkdown: string, finalizedMarkdown: string) => {
    if (finalizedMarkdown !== originalMarkdown) {
      latestMarkdownRef.current = finalizedMarkdown;
      setDraftValue(finalizedMarkdown);
      onValueChange(finalizedMarkdown, false);
    }
  }, [onValueChange, setDraftValue]);

  const collectPendingImageFiles = useCallback((markdown: string): File[] => {
    const files: File[] = [];
    const tokens = extractTempImageTokens(markdown);
    for (let i = 0; i < tokens.length; i += 1) {
      const attachment = registryRef.current.getAttachment(tokens[i]);
      if (attachment?.file) {
        files.push(attachment.file);
      }
    }
    return files;
  }, []);

  const clearPendingCleanup = useCallback(() => {
    const pendingTimeouts = Array.from(pendingCleanupTimeoutRef.current.values());
    for (let i = 0; i < pendingTimeouts.length; i += 1) {
      clearTimeout(pendingTimeouts[i]);
    }
    pendingCleanupTimeoutRef.current.clear();
    registryRef.current.cleanupAllTempAttachments();
  }, []);

  useEffect(() => {
    const next = value ?? '';
    if (next === latestMarkdownRef.current) {
      return;
    }

    // Keep local typing state authoritative while focused to avoid
    // cursor jumps when the Formik wrapper syncs value asynchronously.
    if (isFieldFocusedRef.current) {
      return;
    }

    syncFromExternalValue(next);
  }, [isFieldFocusedRef, syncFromExternalValue, value]);

  const finalizeMarkdown = useCallback(async (
    markdown = latestMarkdownRef.current,
    uploadEntityIdOverride?: string,
  ): Promise<string> => {
    const finalized = await finalizeTempImageUrls(markdown, registryRef.current, (token) => {
      removeFinalizedToken(token);
    }, {
      uploadEntityIdOverride,
    });

    applyFinalizedMarkdown(markdown, finalized);

    return finalized;
  }, [applyFinalizedMarkdown, finalizeTempImageUrls, removeFinalizedToken]);

  const getPendingImageFiles = useCallback((): File[] => {
    return collectPendingImageFiles(latestMarkdownRef.current);
  }, [collectPendingImageFiles]);

  useEffect(() => {
    if (!registerMarkdownImagesController) {
      return undefined;
    }

    registerMarkdownImagesController({
      persistTempImages: (uploadEntityIdOverride?: string) => finalizeMarkdown(undefined, uploadEntityIdOverride),
      getPendingImageFiles,
    });

    return () => registerMarkdownImagesController({
      persistTempImages: () => Promise.resolve(latestMarkdownRef.current),
      getPendingImageFiles: () => [],
    });
  }, [finalizeMarkdown, getPendingImageFiles, registerMarkdownImagesController]);

  const cleanupRemovedAttachments = useCallback((markdown: string, force = false) => {
    cleanupRemovedTempAttachments({
      pendingCleanupTimeoutRef,
      latestMarkdownRef,
      isFieldFocusedRef,
      registry: registryRef.current,
      delayMs: tempCleanupDelayMs,
    }, markdown, force);
  }, [isFieldFocusedRef, tempCleanupDelayMs]);

  useEffect(() => {
    return () => {
      clearPendingCleanup();
    };
  }, [clearPendingCleanup]);

  const interactions = useMarkdownImageInteractions({
    activeTab,
    disabled,
    isImageUploadEnabled,
    t_i18n,
    containerRef,
    latestMarkdownRef,
    registryRef,
    pushDraftAndSyncLatest,
    maxImageSizeBytes,
  });

  return {
    ...interactions,
    cleanupRemovedAttachments,
    finalizeMarkdown,
    syncLatestMarkdown,
    latestMarkdownRef,
    pendingCleanupTimeoutRef,
    registryRef,
  };
};

export default useMarkdownImages;
