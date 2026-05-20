import { describe, expect, it } from 'vitest';
import { resolveNoteEmbeddedImageUrl } from './note-utils';

describe('note-utils', () => {
  it('returns null for empty URL', () => {
    expect(resolveNoteEmbeddedImageUrl('', 'note-1')).toBeNull();
  });

  it('returns non-embedded URLs unchanged', () => {
    expect(resolveNoteEmbeddedImageUrl('https://example.org/image.png', 'note-1')).toBe('https://example.org/image.png');
    expect(resolveNoteEmbeddedImageUrl('/storage/view/abc', 'note-1')).toBe('/storage/view/abc');
  });

  it('resolves short embedded filename via note id', () => {
    const resolved = resolveNoteEmbeddedImageUrl('embedded/image-a.png', 'note-123');
    expect(resolved).toBe('/storage/view/embedded/Note/note-123/image-a.png');
  });

  it('resolves leading-slash embedded filename via note id', () => {
    const resolved = resolveNoteEmbeddedImageUrl('/embedded/image-b.png', 'note-123');
    expect(resolved).toBe('/storage/view/embedded/Note/note-123/image-b.png');
  });

  it('resolves full embedded storage paths to storage/view URL', () => {
    const fullPath = 'embedded/Note/note-123/image-c.png';
    expect(resolveNoteEmbeddedImageUrl(fullPath, 'note-999')).toBe('/storage/view/embedded/Note/note-123/image-c.png');
  });

  it('returns null when embedded path has no filename', () => {
    expect(resolveNoteEmbeddedImageUrl('embedded/', 'note-1')).toBeNull();
  });

  it('returns null when note id is missing for short embedded URL', () => {
    expect(resolveNoteEmbeddedImageUrl('embedded/image-d.png', '')).toBeNull();
  });
});
