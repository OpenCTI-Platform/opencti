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
  // <style> elements would apply their rules to the whole application,
  // an open <dialog> is positioned outside of the content flow.
  FORBID_TAGS: ['style', 'dialog'],
  // Popovers are rendered in the top layer, above the whole application.
  FORBID_ATTR: ['popover', 'popovertarget', 'popovertargetaction'],
};

// CSS properties that take an element out of the content flow (e.g. a
// full-screen overlay). The container below already keeps such elements
// inside its box; they are also removed from the content itself.
const FORBIDDEN_STYLE_PROPERTIES = ['position', 'z-index', 'inset', 'top', 'right', 'bottom', 'left'];

// Values loading a resource (tracking pixels): `url(...)`, and `image-set(...)`
// which also accepts plain strings as URLs.
const RESOURCE_VALUE_REGEX = /url\(|image-set\(/i;

const isForbiddenDeclaration = (property: string, value: string) => FORBIDDEN_STYLE_PROPERTIES.includes(property)
  || property.startsWith('border-image')
  || RESOURCE_VALUE_REGEX.test(value);

// Use the browser's own CSS parser (via CSSStyleDeclaration) instead of naive
// string splitting: it normalizes CSS escapes (e.g. `po\73ition`), expands
// shorthands into longhands and safely handles values that legitimately
// contain `;` (e.g. data-URIs).
const sanitizeStyleAttribute = (styleValue: string) => {
  const span = document.createElement('span');
  span.setAttribute('style', styleValue);
  // Copy the property names first: removing properties mutates span.style.
  Array.from(span.style).forEach((property) => {
    if (isForbiddenDeclaration(property, span.style.getPropertyValue(property))) {
      span.style.removeProperty(property);
    }
  });
  return span.style.cssText;
};

// Dedicated instance: hooks registered on the default `purify` export would
// also apply to every other sanitize call of the application.
const htmlDisplayPurify = purify(window);

htmlDisplayPurify.addHook('uponSanitizeAttribute', (_node, data) => {
  if (data.attrName === 'style' && data.attrValue) {
    data.attrValue = sanitizeStyleAttribute(data.attrValue);
  }
});

// Keeps the content inside the container box whatever its styles: the container
// becomes the containing block of fixed and absolute descendants and their
// stacking context, and anything moved outside of it (transform, translate,
// negative margins...) is clipped. Inline styles produced by the rich-text
// editor (borders, backgrounds, indentation...) are left untouched.
const CONTAINER_STYLE = { contain: 'paint' };

const HtmlDisplay: FunctionComponent<HtmlDisplayProps> = ({ content, limit }) => {
  if (isEmptyField(content)) {
    return (
      <FieldOrEmpty source={content}>{content}</FieldOrEmpty>
    );
  }
  const sanitize = (html: string) => htmlDisplayPurify.sanitize(html, SANITIZE_CONFIG);
  return (
    <div className="ck-content" style={CONTAINER_STYLE}>
      {limit ? parse(sanitize(truncate(content, limit))) : parse(sanitize(content))}
    </div>
  );
};

export default HtmlDisplay;
