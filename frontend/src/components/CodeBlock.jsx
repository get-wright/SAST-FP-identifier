import { useEffect, useState } from "preact/hooks";
import hljs from "highlight.js/lib/core";
import python from "highlight.js/lib/languages/python";
import javascript from "highlight.js/lib/languages/javascript";
import typescript from "highlight.js/lib/languages/typescript";
import go from "highlight.js/lib/languages/go";
import java from "highlight.js/lib/languages/java";
import dockerfile from "highlight.js/lib/languages/dockerfile";
import xml from "highlight.js/lib/languages/xml";
import css from "highlight.js/lib/languages/css";
import bash from "highlight.js/lib/languages/bash";
import "highlight.js/styles/github-dark.css";
import styles from "./CodeBlock.module.css";

hljs.registerLanguage("python", python);
hljs.registerLanguage("javascript", javascript);
hljs.registerLanguage("typescript", typescript);
hljs.registerLanguage("go", go);
hljs.registerLanguage("java", java);
hljs.registerLanguage("dockerfile", dockerfile);
hljs.registerLanguage("xml", xml);
hljs.registerLanguage("css", css);
hljs.registerLanguage("bash", bash);

const EXT_LANG = {
  py: "python",
  js: "javascript",
  jsx: "javascript",
  ts: "typescript",
  tsx: "typescript",
  go: "go",
  java: "java",
  dockerfile: "dockerfile",
  html: "xml",
  css: "css",
  sh: "bash",
  bash: "bash",
  yml: "yaml",
  yaml: "yaml",
};

export function detectLang(path) {
  if (!path) return null;
  if (path.toLowerCase().includes("dockerfile")) return "dockerfile";
  const ext = path.split(".").pop()?.toLowerCase();
  return EXT_LANG[ext] || null;
}

// Parse raw code string into Array<{ num: number, text: string }>
function parseLines(code) {
  if (!code) return [];
  const raw = code.split("\n");
  // Remove trailing empty line from split
  if (raw.length > 0 && raw[raw.length - 1] === "") raw.pop();

  // Detect "  37 | ENTRYPOINT..." prefix format
  const prefixRe = /^\s*(\d+)\s*[|:]\s?/;
  const hasPrefixes = raw.length > 0 && prefixRe.test(raw[0]);

  if (hasPrefixes) {
    return raw
      .map((l) => {
        const m = prefixRe.exec(l);
        if (m) return { num: parseInt(m[1], 10), text: l.slice(m[0].length) };
        return { num: 0, text: l };
      })
      .filter((l) => l.num > 0);
  }

  return raw.map((text, i) => ({ num: i + 1, text }));
}

function doHighlight(text, language) {
  const lang = language && hljs.getLanguage(language) ? language : null;
  const result = lang
    ? hljs.highlight(text, { language: lang })
    : hljs.highlightAuto(text);
  return result.value;
}

export function CodeBlock({ code, highlightLine, language }) {
  const allLines = parseLines(code);
  const isLarge = allLines.length > 500;

  // Window ±10 lines around highlightLine when code is long (>25 lines)
  let displayLines = allLines;
  if (allLines.length > 25 && highlightLine) {
    const idx = allLines.findIndex((l) => l.num === highlightLine);
    if (idx >= 0) {
      const start = Math.max(0, idx - 10);
      const end = Math.min(allLines.length, idx + 11);
      displayLines = allLines.slice(start, end);
    }
  }

  const rawText = displayLines.map((l) => l.text).join("\n");

  // For large files, start with raw text and upgrade in idle callback
  const [highlighted, setHighlighted] = useState(() =>
    isLarge ? null : doHighlight(rawText, language)
  );

  useEffect(() => {
    if (isLarge) {
      const cb = () => setHighlighted(doHighlight(rawText, language));
      if (typeof requestIdleCallback !== "undefined") {
        const id = requestIdleCallback(cb);
        return () => cancelIdleCallback(id);
      } else {
        const id = setTimeout(cb, 0);
        return () => clearTimeout(id);
      }
    } else {
      setHighlighted(doHighlight(rawText, language));
    }
  }, [rawText, language, isLarge]);

  // Split highlighted HTML back into per-line spans.
  // hljs output is a single string — we split on newlines outside tags.
  const hlLines = highlighted ? splitHighlightedLines(highlighted) : null;

  if (displayLines.length === 0) {
    return <div class={styles.empty}>No code available</div>;
  }

  return (
    <div class={styles.wrapper}>
      <pre class={styles.pre}>
        {displayLines.map((line, i) => {
          const isHl = line.num === highlightLine;
          const lineHtml = hlLines ? hlLines[i] ?? "" : escapeHtml(line.text);
          return (
            <div key={line.num} class={`${styles.line} ${isHl ? styles.hlLine : ""}`}>
              <span class={styles.lineNum}>{line.num}</span>
              <code
                class={`hljs ${styles.lineCode}`}
                // eslint-disable-next-line react/no-danger
                dangerouslySetInnerHTML={{ __html: lineHtml }}
              />
            </div>
          );
        })}
      </pre>
    </div>
  );
}

function escapeHtml(str) {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

/**
 * Split hljs HTML output into per-line strings.
 * hljs wraps tokens in <span> tags; we need to split on \n while keeping
 * open/close spans balanced per line (re-open/close cross-line spans).
 */
function splitHighlightedLines(html) {
  const lines = [];
  let current = "";
  // Track open spans so we can close and reopen across line boundaries
  const openSpans = [];

  let i = 0;
  while (i < html.length) {
    if (html[i] === "\n") {
      lines.push(current + openSpans.map(() => "</span>").join(""));
      current = openSpans.map((s) => s).join("");
      i++;
    } else if (html[i] === "<") {
      // Find end of tag
      const end = html.indexOf(">", i);
      if (end === -1) {
        current += html.slice(i);
        break;
      }
      const tag = html.slice(i, end + 1);
      current += tag;
      if (tag.startsWith("</")) {
        openSpans.pop();
      } else if (!tag.endsWith("/>")) {
        openSpans.push(tag);
      }
      i = end + 1;
    } else {
      current += html[i];
      i++;
    }
  }
  if (current) lines.push(current);
  return lines;
}
