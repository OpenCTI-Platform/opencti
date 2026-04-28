import { useCallback, useRef } from 'react';
import type { MarkdownImagesController } from '../../components/fields/markdownField/MarkdownField';

const useMarkdownCreationFilesInput = () => {
  const markdownControllerRef = useRef<MarkdownImagesController | null>(null);

  const registerMarkdownImagesController = useCallback((controller: MarkdownImagesController) => {
    markdownControllerRef.current = controller;
  }, []);

  const buildMarkdownFilesInput = useCallback(() => {
    const markdownTempFiles = markdownControllerRef.current?.getPendingImageFiles() ?? [];
    return markdownTempFiles.length > 0
      ? { files: markdownTempFiles, embedded: markdownTempFiles.map(() => true) }
      : {};
  }, []);

  return {
    buildMarkdownFilesInput,
    registerMarkdownImagesController,
  };
};

export default useMarkdownCreationFilesInput;