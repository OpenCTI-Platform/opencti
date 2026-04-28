import { useCallback, useRef } from 'react';
import type { MarkdownImagesController } from '../../components/fields/markdownField/MarkdownField';

const useMarkdownCreationFilesInput = () => {
  const markdownControllerRef = useRef<MarkdownImagesController | null>(null);

  const registerMarkdownImagesController = useCallback((controller: MarkdownImagesController) => {
    markdownControllerRef.current = controller;
  }, []);

  const buildCreationFilesInput = useCallback((extraFiles: File[] = []) => {
    const markdownTempFiles = markdownControllerRef.current?.getPendingImageFiles() ?? [];
    const files = [...markdownTempFiles, ...extraFiles];
    return files.length > 0
      ? { files, embedded: files.map((_, index) => index < markdownTempFiles.length) }
      : {};
  }, []);

  const buildMarkdownFilesInput = useCallback(() => {
    return buildCreationFilesInput();
  }, [buildCreationFilesInput]);

  return {
    buildCreationFilesInput,
    buildMarkdownFilesInput,
    registerMarkdownImagesController,
  };
};

export default useMarkdownCreationFilesInput;
