/**
 * A stand-in for `CanvasRenderingContext2D` in unit tests: jsdom ships no canvas, and painters
 * are verified through what they ask the context to do. Every method call is recorded with its
 * arguments and the style in force at that moment; text measures one unit per character per
 * pixel of font size, so truncation is predictable.
 */
export interface RecordedCall {
  method: string;
  args: unknown[];
  fillStyle: unknown;
  strokeStyle: unknown;
  globalAlpha: number;
  lineWidth: number;
  lineDash: number[];
  font: string;
}

export interface RecordingContext extends CanvasRenderingContext2D {
  calls: RecordedCall[];
  callsOf: (method: string) => RecordedCall[];
  texts: () => string[];
  reset: () => void;
}

const fontSize = (font: string) => {
  const match = /([\d.]+)px/.exec(font);
  return match ? Number(match[1]) : 10;
};

export const createRecordingContext = (): RecordingContext => {
  const calls: RecordedCall[] = [];
  const stack: Record<string, unknown>[] = [];
  let lineDash: number[] = [];
  const state: Record<string, unknown> = {
    fillStyle: '#000000',
    strokeStyle: '#000000',
    globalAlpha: 1,
    lineWidth: 1,
    font: '10px sans-serif',
    textAlign: 'start',
    textBaseline: 'alphabetic',
    lineCap: 'butt',
    lineJoin: 'miter',
    globalCompositeOperation: 'source-over',
    shadowBlur: 0,
    shadowColor: 'transparent',
    imageSmoothingEnabled: true,
  };
  const record = (method: string, args: unknown[]) => {
    calls.push({
      method,
      args,
      fillStyle: state.fillStyle,
      strokeStyle: state.strokeStyle,
      globalAlpha: state.globalAlpha as number,
      lineWidth: state.lineWidth as number,
      lineDash: [...lineDash],
      font: state.font as string,
    });
  };
  const methods: Record<string, (...args: unknown[]) => unknown> = {
    save: () => {
      stack.push({ ...state, lineDash: [...lineDash] });
    },
    restore: () => {
      const previous = stack.pop();
      if (previous) {
        lineDash = previous.lineDash as number[];
        Object.assign(state, previous);
        delete state.lineDash;
      }
    },
    setLineDash: (segments: unknown) => {
      lineDash = [...(segments as number[])];
    },
    getLineDash: () => [...lineDash],
    measureText: (text: unknown) => ({ width: String(text).length * fontSize(state.font as string) * 0.5 }),
    createLinearGradient: () => ({ addColorStop: () => undefined }),
    createRadialGradient: () => ({ addColorStop: () => undefined }),
    getTransform: () => ({ a: 1, b: 0, c: 0, d: 1, e: 0, f: 0 }),
  };
  const recorded = [
    'beginPath', 'closePath', 'moveTo', 'lineTo', 'arc', 'arcTo', 'ellipse', 'rect', 'roundRect',
    'quadraticCurveTo', 'bezierCurveTo', 'fill', 'stroke', 'fillRect', 'strokeRect', 'clearRect',
    'fillText', 'strokeText', 'drawImage', 'translate', 'rotate', 'scale', 'setTransform', 'clip',
  ];
  const target: Record<string, unknown> = {
    calls,
    callsOf: (method: string) => calls.filter((call) => call.method === method),
    texts: () => calls.filter((call) => call.method === 'fillText').map((call) => String(call.args[0])),
    reset: () => {
      calls.length = 0;
    },
  };
  return new Proxy(target, {
    get(obj, property: string) {
      if (property in obj) return obj[property];
      if (property in methods) return methods[property];
      if (recorded.includes(property)) {
        return (...args: unknown[]) => {
          record(property, args);
        };
      }
      return state[property];
    },
    set(_obj, property: string, value) {
      state[property] = value;
      return true;
    },
  }) as unknown as RecordingContext;
};
