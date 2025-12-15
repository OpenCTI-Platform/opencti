import { CKEditor as ReactCKEditor } from '@ckeditor/ckeditor5-react';
import {
  Editor,
  Alignment,
  Autoformat,
  AutoImage,
  AutoLink,
  Base64UploadAdapter,
  BlockQuote,
  Bold,
  ClassicEditor,
  Code,
  CodeBlock,
  Essentials,
  FontBackgroundColor,
  FontColor,
  FontFamily,
  FontSize,
  Heading,
  Highlight,
  HorizontalLine,
  ImageCaption,
  ImageInsert,
  ImageResize,
  ImageStyle,
  ImageToolbar,
  Indent,
  IndentBlock,
  Italic,
  Link,
  LinkImage,
  ListProperties,
  Mention,
  Paragraph,
  PasteFromOffice,
  RemoveFormat,
  SourceEditing,
  SpecialCharacters,
  SpecialCharactersCurrency,
  SpecialCharactersEssentials,
  Strikethrough,
  Subscript,
  Superscript,
  List,
  Table,
  TodoList,
  TableCaption,
  TableColumnResize,
  TableToolbar,
  Underline,
  ImageEditing,
  ImageBlockEditing,
  EditorConfig,
  ImageTextAlternative,
  PageBreak,
  GeneralHtmlSupport,
} from 'ckeditor5';
import React from 'react';
import { useIntl } from 'react-intl';

// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore

import de from 'ckeditor5/translations/de.js';
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore

import en from 'ckeditor5/translations/en.js';
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore

import es from 'ckeditor5/translations/es.js';
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore

import fr from 'ckeditor5/translations/fr.js';
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore

import ja from 'ckeditor5/translations/ja.js';
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore

import ko from 'ckeditor5/translations/ko.js';
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore

import zh from 'ckeditor5/translations/zh.js';

const CKEDITOR_DEFAULT_CONFIG: EditorConfig = {
  htmlSupport: {
    allow: [
      { name: 'div', classes: true, styles: true },
      { name: 'span', classes: true, styles: true },
    ],
  },
  translations: [de, en, es, fr, ja, ko, zh],
  plugins: [
    Alignment,
    AutoImage,
    Autoformat,
    AutoLink,
    Base64UploadAdapter,
    BlockQuote,
    Bold,
    Code,
    CodeBlock,
    Essentials,
    FontBackgroundColor,
    FontColor,
    FontFamily,
    FontSize,
    GeneralHtmlSupport,
    Heading,
    Highlight,
    HorizontalLine,
    ImageBlockEditing,
    ImageCaption,
    ImageEditing,
    ImageInsert,
    ImageResize,
    ImageStyle,
    ImageToolbar,
    ImageTextAlternative,
    Indent,
    IndentBlock,
    Italic,
    Link,
    LinkImage,
    List,
    ListProperties,
    Mention,
    PageBreak,
    Paragraph,
    PasteFromOffice,
    RemoveFormat,
    SourceEditing,
    SpecialCharacters,
    SpecialCharactersCurrency,
    SpecialCharactersEssentials,
    Strikethrough,
    Subscript,
    Superscript,
    Table,
    TableCaption,
    TableColumnResize,
    TableToolbar,
    TodoList,
    Underline,
  ],
  toolbar: {
    items: [
      'heading',
      'fontFamily',
      'fontSize',
      'alignment',
      'pageBreak',
      '|',
      'bold',
      'italic',
      'underline',
      'strikethrough',
      'link',
      'fontColor',
      'fontBackgroundColor',
      'highlight',
      '|',
      'bulletedList',
      'numberedList',
      'outdent',
      'indent',
      'todoList',
      '|',
      'imageInsert',
      'blockQuote',
      'code',
      'codeBlock',
      'insertTable',
      'specialCharacters',
      'subscript',
      'superscript',
      'horizontalLine',
      '|',
      'sourceEditing',
      'removeFormat',
      'undo',
      'redo',
    ],
  },
  image: {
    resizeUnit: 'px',
    toolbar: [
      'imageTextAlternative',
      'toggleImageCaption',
      'imageStyle:block',
      'imageStyle:side',
      'linkImage',
    ],
  },
  table: {
    contentToolbar: [
      'tableColumn',
      'tableRow',
      'mergeTableCells',
    ],
  },
  heading: {
    options: [
      { class: 'ck-heading_paragraph', model: 'paragraph', title: 'Paragraph' },
      { class: 'ck-heading_heading1', model: 'heading1', view: 'h1', title: 'Heading 1' },
      { class: 'ck-heading_heading2', model: 'heading2', view: 'h2', title: 'Heading 2' },
      { class: 'ck-heading_heading3', model: 'heading3', view: 'h3', title: 'Heading 3' },
    ],
  },
};

type CKEditorProps<T extends Editor> = Omit<ReactCKEditor<T>['props'], 'editor' | 'config'>;

const CKEditor = (props: CKEditorProps<ClassicEditor>) => {
  const { locale } = useIntl();

  const config: EditorConfig = {
    ...CKEDITOR_DEFAULT_CONFIG,
    language: locale.slice(0, 2),
  };

  return (
    <ReactCKEditor
      editor={ClassicEditor}
      config={config}
      {...props}
      onReady={(editor) => { // to detect changes in source editing mode
        props.onReady?.(editor); // call parent-provided onReady if defined
        if (editor.plugins.has('SourceEditing')) {
          const sourceEditingPlugin = editor.plugins.get('SourceEditing');
          sourceEditingPlugin.on('change:isSourceEditingMode', (evt, _, isSourceEditingMode) => {
            if (isSourceEditingMode) {
              const textarea = document.querySelector('.ck-source-editing-area textarea') as HTMLTextAreaElement;
              if (textarea) {
                textarea.addEventListener('input', () => {
                  props.onChange?.(evt, editor); // trigger manually onChange
                });
              }
            }
          });
        }
      }}
    />
  );
};

export default CKEditor;
