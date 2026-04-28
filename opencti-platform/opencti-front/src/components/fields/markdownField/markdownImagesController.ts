export type MarkdownImagesController = {
  persistTempImages: (uploadEntityIdOverride?: string) => Promise<string>;
  getPendingImageFiles: () => File[];
};
