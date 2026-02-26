/**
 * Module augmentation for @tiptap/core Commands interface.
 *
 * TipTap StarterKit bundles sub-extensions (bold, italic, heading, …) as nested
 * dependencies. Their `declare module '@tiptap/core'` augmentations are invisible
 * to TypeScript because they live under starter-kit/node_modules/. We replicate
 * the relevant command signatures here so that ChainedCommands, SingleCommands,
 * and editor.can() are fully typed without `as any` casts.
 */

import '@tiptap/core';

declare module '@tiptap/core' {
  interface Commands<ReturnType> {
    bold: {
      setBold: () => ReturnType;
      toggleBold: () => ReturnType;
      unsetBold: () => ReturnType;
    };
    italic: {
      setItalic: () => ReturnType;
      toggleItalic: () => ReturnType;
      unsetItalic: () => ReturnType;
    };
    strike: {
      setStrike: () => ReturnType;
      toggleStrike: () => ReturnType;
      unsetStrike: () => ReturnType;
    };
    code: {
      setCode: () => ReturnType;
      toggleCode: () => ReturnType;
      unsetCode: () => ReturnType;
    };
    codeBlock: {
      setCodeBlock: (attributes?: { language: string }) => ReturnType;
      toggleCodeBlock: (attributes?: { language: string }) => ReturnType;
    };
    heading: {
      setHeading: (attributes: { level: 1 | 2 | 3 | 4 | 5 | 6 }) => ReturnType;
      toggleHeading: (attributes: { level: 1 | 2 | 3 | 4 | 5 | 6 }) => ReturnType;
    };
    paragraph: {
      setParagraph: () => ReturnType;
    };
    blockQuote: {
      setBlockquote: () => ReturnType;
      toggleBlockquote: () => ReturnType;
      unsetBlockquote: () => ReturnType;
    };
    horizontalRule: {
      setHorizontalRule: () => ReturnType;
    };
  }
}
