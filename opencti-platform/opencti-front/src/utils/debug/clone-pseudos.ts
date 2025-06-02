import type { Options } from './types';
import { uuid, getStyleProperties } from './util';

type Pseudo = ':before' | ':after';

function formatCSSText(style: CSSStyleDeclaration) {
  const content = style.getPropertyValue('content');
  return `${style.cssText} content: '${content.replace(/'|"/g, '')}';`;
}

function formatCSSProperties(style: CSSStyleDeclaration, options: Options) {
  return getStyleProperties(options)
    .map((name) => {
      const value = style.getPropertyValue(name);
      const priority = style.getPropertyPriority(name);

      return `${name}: ${value}${priority ? ' !important' : ''};`;
    })
    .join(' ');
}

function getPseudoElementStyle(
  className: string,
  pseudo: Pseudo,
  style: CSSStyleDeclaration,
  options: Options,
): Text {
  const selector = `.${className}:${pseudo}`;
  const cssText = style.cssText
    ? formatCSSText(style)
    : formatCSSProperties(style, options);

  return document.createTextNode(`${selector}{${cssText}}`);
}

function clonePseudoElement<T extends HTMLElement>(
  nativeNode: T,
  clonedNode: T,
  pseudo: Pseudo,
  options: Options,
) {
  const style = window.getComputedStyle(nativeNode, pseudo);
  const content = style.getPropertyValue('content');
  if (content === '' || content === 'none') {
    return;
  }

  const className = uuid();
  try {
    clonedNode.className = `${clonedNode.className} ${className}`;
  } catch (err) {
    return;
  }

  const styleElement = document.createElement('style');
  styleElement.appendChild(
    getPseudoElementStyle(className, pseudo, style, options),
  );
  clonedNode.appendChild(styleElement);
}

export function clonePseudoElements<T extends HTMLElement>(
  nativeNode: T,
  clonedNode: T,
  options: Options,
) {
  clonePseudoElement(nativeNode, clonedNode, ':before', options);
  clonePseudoElement(nativeNode, clonedNode, ':after', options);
}
