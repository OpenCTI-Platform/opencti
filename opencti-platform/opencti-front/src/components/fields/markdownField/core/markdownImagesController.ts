export type MarkdownImagesTab = 'write' | 'preview';

export type MarkdownImagesController = {
  persistTempImages: (uploadEntityIdOverride?: string) => Promise<string>;
  getPendingImageFiles: () => File[];
};
