const fs   = require("fs");
const vm   = require("vm");
const path = require("path");

const RULES = [
  {
    id       : "XSS_INNER_HTML",
    severity : "HIGH",
    pattern  : /\.innerHTML\s*[+]?=/,
    filter   : (line) => !/\.innerHTML\s*=\s*["'`][^"'`]*["'`]\s*;/.test(line),
    message  : "Affectation innerHTML avec une variable — risque XSS",
  },
  {
    id       : "XSS_OUTER_HTML",
    severity : "HIGH",
    pattern  : /\.outerHTML\s*[+]?=/,
    filter   : (line) => !/\.outerHTML\s*=\s*["'`][^"'`]*["'`]\s*;/.test(line),
    message  : "Affectation outerHTML avec une variable — risque XSS",
  },
  {
    id       : "XSS_DOCUMENT_WRITE",
    severity : "HIGH",
    pattern  : /document\s*\.\s*write\s*\(/,
    filter   : (line) => !/document\.write\s*\(\s*["'`][^"'`]*["'`]\s*\)/.test(line),
    message  : "document.write() avec variable — risque XSS",
  },
  {
    id       : "XSS_INSERT_ADJACENT",
    severity : "MEDIUM",
    pattern  : /\.insertAdjacentHTML\s*\(/,
    message  : "insertAdjacentHTML() — vérifier que le HTML inséré est assaini",
  },
  {
    id       : "XSS_SET_ATTRIBUTE_EVENT",
    severity : "HIGH",
    pattern  : /\.setAttribute\s*\(\s*["'`]on\w+["'`]/,
    message  : "setAttribute() sur un handler d'événement (onclick…) — risque XSS",
  },

  {
    id       : "CODE_INJECTION_EVAL",
    severity : "CRITICAL",
    pattern  : /\beval\s*\(/,
    message  : "eval() détecté — exécution de code dynamique, risque d'injection",
  },
  {
    id       : "CODE_INJECTION_FUNCTION",
    severity : "CRITICAL",
    pattern  : /new\s+Function\s*\(/,
    message  : "new Function() — équivalent à eval(), risque d'injection de code",
  },
  {
    id       : "CODE_INJECTION_SETTIMEOUT",
    severity : "HIGH",
    pattern  : /\b(setTimeout|setInterval)\s*\(\s*(?!function|=>|\()(?:[^"'`])/,
    message  : "setTimeout/setInterval avec une variable (code injection possible)",
  },

  {
    id       : "SQL_INJECTION_CONCAT",
    severity : "CRITICAL",
    pattern  : /["'`]\s*(SELECT|INSERT|UPDATE|DELETE|DROP|UNION)[\s\S]*?["'`]\s*\+/i,
    message  : "Injection SQL potentielle — concaténation dans une requête SQL",
  },
  {
    id       : "SQL_INJECTION_TEMPLATE",
    severity : "CRITICAL",
    pattern  : /`[^`]*(SELECT|INSERT|UPDATE|DELETE|DROP|UNION)[^`]*\$\{/i,
    message  : "Injection SQL potentielle — template literal dans une requête SQL",
  },


  {
    id       : "OPEN_REDIRECT",
    severity : "MEDIUM",
    pattern  : /(?:window\.location|location\.href|location\.replace)\s*[=\(]/,
    filter   : (line) => !/=\s*["'`]https?:\/\//.test(line),
    message  : "Redirection via location avec variable — risque open redirect",
  },

  {
    id       : "SENSITIVE_COOKIE_ACCESS",
    severity : "LOW",
    pattern  : /document\.cookie/,
    message  : "Accès à document.cookie — vérifier qu'il n'est pas exposé côté client",
  },
  {
    id       : "LOCALSTORAGE_SENSITIVE",
    severity : "LOW",
    pattern  : /localStorage\.(getItem|setItem)\s*\(\s*["'`](token|password|secret|key|auth)/i,
    message  : "Stockage d'une donnée sensible dans localStorage",
  },
];


function validateSyntax(code, filepath) {
  try {
    new vm.Script(code, { filename: filepath });
    return null;
  } catch (e) {
    return e.message;
  }
}

function scanCode(code, filepath, extraRules) {
  const findings = [];
  const lines    = code.split("\n");
  const rules    = extraRules ? [...RULES, ...extraRules] : RULES;

  lines.forEach((line, idx) => {
    const lineNo = idx + 1;
    const trimmed = line.trimStart();
    if (trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("/*")) {
      return;
    }

    for (const rule of rules) {
      if (!rule.pattern.test(line)) continue;
      if (rule.filter && !rule.filter(line)) continue;
      const match  = line.match(rule.pattern);
      const column = match ? match.index : 0;

      findings.push({
        file       : filepath,
        line       : lineNo,
        column     : column,
        rule_id    : rule.id,
        severity   : rule.severity,
        description: rule.message,
      });
    }
  });

  return findings;
}

function main() {
  const args     = process.argv.slice(2);
  const filepath = args[0];

  if (!filepath) {
    process.stderr.write("Usage: node js_scanner.js <filepath>\n");
    process.exit(1);
  }

  let code;
  try {
    code = fs.readFileSync(filepath, "utf-8");
  } catch (e) {
    process.stderr.write(`Erreur de lecture: ${e.message}\n`);
    process.exit(1);
  }

  const syntaxError = validateSyntax(code, filepath);
  if (syntaxError) {
    process.stderr.write(`Erreur de syntaxe JS dans ${path.basename(filepath)}: ${syntaxError}\n`);
  }

  const findings = scanCode(code, filepath);
  process.stdout.write(JSON.stringify(findings, null, 2));
}

main();
