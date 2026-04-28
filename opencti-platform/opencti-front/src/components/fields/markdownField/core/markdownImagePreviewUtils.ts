export const TEMP_IMAGE_SCHEME = 'opencti-image://temp/';
const TEMP_IMAGE_URL_REGEX = /opencti-image:\/\/temp\/([0-9a-fA-F-]+)/g;

export interface InsertResult {
  markdown: string;
  nextCursor: number;
}

export interface TempAttachment {
  token: string;
  file: File;
  blobUrl: string;
  status: 'local';
}

export function extractTempImageTokens(markdown: string): string[] {
  const tokens = new Set<string>();
  let match = TEMP_IMAGE_URL_REGEX.exec(markdown);
  while (match) {
    tokens.add(match[1]);
    match = TEMP_IMAGE_URL_REGEX.exec(markdown);
  }
  return Array.from(tokens);
}

export function replaceTempImageTokenUrl(markdown: string, token: string, finalUrl: string): string {
  return markdown.split(`${TEMP_IMAGE_SCHEME}${token}`).join(finalUrl);
}

export function insertImageAtCursor(
  markdown: string,
  cursorIndex: number,
  token: string,
  alt = 'image',
): InsertResult {
  const insert = `![${alt}](${TEMP_IMAGE_SCHEME}${token})`;
  const before = markdown.slice(0, cursorIndex);
  const after = markdown.slice(cursorIndex);
  return {
    markdown: before + insert + after,
    nextCursor: before.length + insert.length,
  };
}

export class MarkdownTempAttachmentRegistry {
  private readonly registry = new Map<string, TempAttachment>();

  createTempAttachment(file: File): TempAttachment {
    const token = crypto.randomUUID();
    const blobUrl = URL.createObjectURL(file);
    const attachment: TempAttachment = { token, file, blobUrl, status: 'local' };
    this.registry.set(token, attachment);
    return attachment;
  }

  removeTempAttachment(token: string): void {
    const attachment = this.registry.get(token);
    if (!attachment) return;
    URL.revokeObjectURL(attachment.blobUrl);
    this.registry.delete(token);
  }

  cleanupAllTempAttachments(): void {
    this.registry.forEach((attachment) => {
      URL.revokeObjectURL(attachment.blobUrl);
    });
    this.registry.clear();
  }

  resolvePreviewImageUrl(url: string): string | null {
    if (!url.startsWith(TEMP_IMAGE_SCHEME)) return url;
    const token = url.slice(TEMP_IMAGE_SCHEME.length);
    return this.registry.get(token)?.blobUrl ?? null;
  }

  getAttachment(token: string): TempAttachment | undefined {
    return this.registry.get(token);
  }

  listTokens(): string[] {
    return Array.from(this.registry.keys());
  }

  get size(): number {
    return this.registry.size;
  }
}
