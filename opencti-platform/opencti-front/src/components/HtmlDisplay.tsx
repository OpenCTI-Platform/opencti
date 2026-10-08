import React, { FunctionComponent } from 'react';
import purify from 'dompurify';
import parse from 'html-react-parser';
import { truncate } from '../utils/String';
import FieldOrEmpty from './FieldOrEmpty';
import { isEmptyField } from '../utils/utils';

interface HtmlDisplayProps {
  content: string | null;
  limit?: number;
}

const SANITIZE_CONFIG = {
  ADD_ATTR: ['data-type', 'data-checked', 'title', 'class', 'href', 'src', 'alt', 'width', 'height', 'data-caption', 'data-href', 'data-title', 'colspan', 'rowspan', 'style'],
  ADD_TAGS: ['figure', 'figcaption', 'th', 'colgroup', 'col'],
  // <style> elements would apply their rules to the whole application,
  // an open <dialog> is positioned outside of the content flow.
  FORBID_TAGS: ['style', 'dialog'],
  // Popovers are rendered in the top layer, above the whole application.
  FORBID_ATTR: ['popover', 'popovertarget', 'popovertargetaction'],
};

// Classes styled by the rich-text stylesheet (`.rich-text-content ...` rules of
// @filigran/rich-text-editor) plus the mapping highlights. Other classes are
// dropped so content cannot reuse the application's own layout classes.
const ALLOWED_CLASSES = [
  'image',
  'image-figure',
  'image-style-side',
  'marker-blue',
  'marker-green',
  'marker-pink',
  'marker-yellow',
  'page-break',
  'pen-green',
  'pen-red',
  'table',
  'text-big',
  'text-huge',
  'text-small',
  'text-tiny',
  'tiptap-task-item',
  'todo-list',
  'todo-list__label',
];

const sanitizeClassAttribute = (classValue: string) => classValue
  .split(/\s+/)
  .filter((className) => ALLOWED_CLASSES.includes(className))
  .join(' ');

// Inline CSS properties produced by the rich-text editor. Anything else is
// dropped: a denylist cannot cover every way to move content outside of its
// container (transform, translate, negative margins...).
// Shorthands are listed by name and also match their longhands
// (e.g. `text-decoration` matches `text-decoration-line`).
const ALLOWED_STYLE_PROPERTIES = [
  'color',
  'background-color',
  'font',
  'line-height',
  'text-align',
  'text-decoration',
  'vertical-align',
  'width',
  'min-width',
  'height',
  'table-layout',
];

// Indentation is the only margin the editor emits; only positive lengths are kept.
const INDENT_STYLE_PROPERTY = 'margin-left';
const POSITIVE_LENGTH_REGEX = /^\d+(\.\d+)?(px|em|rem|%)?$/;

const isAllowedStyleProperty = (property: string, value: string) => {
  if (property === INDENT_STYLE_PROPERTY) {
    return POSITIVE_LENGTH_REGEX.test(value);
  }
  return ALLOWED_STYLE_PROPERTIES.some((allowed) => property === allowed || property.startsWith(`${allowed}-`));
};

// Use the browser's own CSS parser (via CSSStyleDeclaration) instead of naive
// string splitting: it normalizes CSS escapes (e.g. `po\73ition`) and safely
// handles values that legitimately contain `;` (e.g. data-URIs).
const sanitizeStyleAttribute = (styleValue: string) => {
  const span = document.createElement('span');
  span.setAttribute('style', styleValue);
  // Copy the property names first: removing properties mutates span.style.
  Array.from(span.style).forEach((property) => {
    if (!isAllowedStyleProperty(property, span.style.getPropertyValue(property))) {
      span.style.removeProperty(property);
    }
  });
  return span.style.cssText;
};

// Dedicated instance: hooks registered on the default `purify` export would
// also apply to every other sanitize call of the application.
const htmlDisplayPurify = purify(window);

// Keep rich-text formatting only, so content stays within its container.
htmlDisplayPurify.addHook('uponSanitizeAttribute', (_node, data) => {
  if (data.attrName === 'style' && data.attrValue) {
    data.attrValue = sanitizeStyleAttribute(data.attrValue);
  }
  if (data.attrName === 'class' && data.attrValue) {
    data.attrValue = sanitizeClassAttribute(data.attrValue);
  }
});

const HtmlDisplay: FunctionComponent<HtmlDisplayProps> = ({ content, limit }) => {
  if (isEmptyField(content)) {
    return (
      <FieldOrEmpty source={content}>{content}</FieldOrEmpty>
    );
  }

  const sanitize = (html: string) => htmlDisplayPurify.sanitize(html, SANITIZE_CONFIG);
  const normalizeImageMetadata = (html: string) => {
    const parser = new DOMParser();
    const doc = parser.parseFromString(html, 'text/html');
    const imgs = Array.from(doc.querySelectorAll('img'));

    imgs.forEach((img) => {
      const dataTitle = img.getAttribute('data-title');
      const dataHref = img.getAttribute('data-href');
      const dataCaption = img.getAttribute('data-caption');

      if (!img.getAttribute('title') && dataTitle) {
        img.setAttribute('title', dataTitle);
      }

      if (dataHref && !img.closest('a')) {
        const a = doc.createElement('a');
        a.setAttribute('href', dataHref);
        a.setAttribute('target', '_blank');
        a.setAttribute('rel', 'noopener noreferrer');
        const parent = img.parentNode;
        if (parent) {
          parent.replaceChild(a, img);
          a.appendChild(img);
        }
      }

      const hasCaption = typeof dataCaption === 'string' && dataCaption.trim() !== '';
      if (hasCaption && !img.closest('figure')) {
        const figure = doc.createElement('figure');
        figure.setAttribute('class', 'image-figure');
        const figcaption = doc.createElement('figcaption');
        figcaption.textContent = dataCaption.trim();

        const maybeAnchor = img.closest('a');
        const mediaNode = maybeAnchor ?? img;
        const parent = mediaNode.parentNode;
        if (parent) {
          parent.replaceChild(figure, mediaNode);
          figure.appendChild(mediaNode);
          figure.appendChild(figcaption);
        }
      }
    });

    const anchors = Array.from(doc.querySelectorAll('a'));
    anchors.forEach((a) => {
      a.setAttribute('target', '_blank');
      a.setAttribute('rel', 'noopener noreferrer');
    });

    return doc.body.innerHTML;
  };

  return (
    <div className="rich-text-content">
      {parse(normalizeImageMetadata(sanitize(limit ? truncate(content, limit) : content)))}
    </div>
  );
};

export default HtmlDisplay;
