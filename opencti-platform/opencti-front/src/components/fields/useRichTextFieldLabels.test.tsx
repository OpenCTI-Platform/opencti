import { renderHook } from '@testing-library/react';
import { ReactNode } from 'react';
import { describe, expect, it } from 'vitest';

import useRichTextFieldLabels from './useRichTextFieldLabels';
import AppIntlProvider from '../AppIntlProvider';
import { UserContext, UserContextType } from '../../utils/hooks/useAuth';
import { createMockUserContext } from '../../utils/tests/test-render';

// testRenderHook puts AppIntlProvider outside UserContext, so its locale is
// always the default one: this wrapper nests them the other way round.
const renderLabels = (locale: string) => renderHook(() => useRichTextFieldLabels(), {
  wrapper: ({ children }: { children: ReactNode }) => (
    <UserContext.Provider value={{ ...createMockUserContext(), locale } as UserContextType}>
      <AppIntlProvider settings={{ platform_language: 'auto', platform_translations: '{}' }}>
        {children}
      </AppIntlProvider>
    </UserContext.Provider>
  ),
}).result.current;

describe('Hook: useRichTextFieldLabels', () => {
  it('translates the toolbar and panel labels', () => {
    const labels = renderLabels('fr-fr');
    expect(labels.bold).toBe('Gras');
    expect(labels.tableOperations).toBe('Options du tableau');
    expect(labels.unsavedChanges).toBe('Vous avez des modifications non enregistrées');
  });

  it('fills in the labels that take a value', () => {
    const labels = renderLabels('fr-fr');
    expect(labels.heading?.(2)).toBe('Titre 2');
    expect(labels.sourceHtmlArea?.('Contenu')).toBe('Source HTML de Contenu');
    expect(labels.imageRejectedSize?.(5 * 1024 * 1024)).toBe('Le fichier est trop volumineux. Taille maximale : 5 Mo');
  });

  it('keeps the English wording in English', () => {
    const labels = renderLabels('en-us');
    expect(labels.heading?.(1)).toBe('Heading 1');
    expect(labels.imageRejectedSize?.(1.5 * 1024 * 1024)).toBe('File is too large. Maximum size: 1.5 MB');
  });

  it('leaves the URL placeholder and table size to the design system defaults', () => {
    const labels = renderLabels('fr-fr');
    expect(labels.urlPlaceholder).toBeUndefined();
    expect(labels.tableSize).toBeUndefined();
  });
});
