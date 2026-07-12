<?php
$RULES = [

    [
        "id"      => "SQL_INJECTION_CONCAT",
        "severity"=> "CRITICAL",
        "pattern" => '/["\']\\s*(SELECT|INSERT|UPDATE|DELETE|DROP|UNION)[\\s\\S]*?["\']\\s*\\.\\s*\\$/i',
        "message" => "Injection SQL potentielle — concaténation de variable dans une requête SQL",
    ],
    [
        "id"      => "SQL_INJECTION_VAR_IN_QUERY",
        "severity"=> "CRITICAL",
        "pattern" => '/(mysql_query|mysqli_query|pg_query|sqlite_query|->query)\s*\(\s*["\'"][^"\']*["\']\s*\.\s*\$/',
        "message" => "Injection SQL potentielle — variable concaténée dans l'appel query()",
    ],
    [
        "id"      => "SQL_INJECTION_SPRINTF",
        "severity"=> "HIGH",
        "pattern" => '/sprintf\s*\(\s*["\'"][^"\'""]*(SELECT|INSERT|UPDATE|DELETE)[^"\']*["\'"].*%s/i',
        "message" => "Injection SQL potentielle — sprintf() avec %s dans une requête SQL",
    ],

    [
        "id"      => "XSS_ECHO_GET_POST",
        "severity"=> "CRITICAL",
        "pattern" => '/echo\s+\$_(GET|POST|REQUEST|COOKIE|SERVER)\s*\[/i',
        "message" => "XSS — echo direct d'une variable superglobale non échappée",
    ],
    [
        "id"      => "XSS_PRINT_GET_POST",
        "severity"=> "CRITICAL",
        "pattern" => '/print\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)\s*\[/i',
        "message" => "XSS — print() d'une variable superglobale non échappée",
    ],
    [
        "id"      => "XSS_ECHO_VAR",
        "severity"=> "HIGH",
        "pattern" => '/echo\s+\$(?!_SESSION|_SERVER)[a-zA-Z_]\w*/i',
        "filter"  => fn($line) => !preg_match('/htmlspecialchars|htmlentities|strip_tags|esc_html|esc_attr/', $line),
        "message" => "XSS possible — echo d'une variable sans htmlspecialchars()/htmlentities()",
    ],

    [
        "id"      => "CMD_INJECTION_EXEC",
        "severity"=> "CRITICAL",
        "pattern" => '/\b(exec|shell_exec|system|passthru|proc_open|popen)\s*\(\s*\$/',
        "message" => "Injection de commande — appel système avec une variable non validée",
    ],
    [
        "id"      => "CMD_INJECTION_BACKTICK",
        "severity"=> "CRITICAL",
        "pattern" => '/`[^`]*\$[^`]*`/',
        "message" => "Injection de commande — exécution via backticks avec une variable",
    ],


    [
        "id"      => "CODE_INJECTION_EVAL",
        "severity"=> "CRITICAL",
        "pattern" => '/\beval\s*\(\s*\$/',
        "message" => "eval() avec une variable — risque d'injection de code arbitraire",
    ],
    [
        "id"      => "CODE_INJECTION_CREATE_FUNCTION",
        "severity"=> "CRITICAL",
        "pattern" => '/\bcreate_function\s*\(/',
        "message" => "create_function() — équivalent à eval(), déprécié depuis PHP 7.2",
    ],
    [
        "id"      => "CODE_INJECTION_PREG_REPLACE_E",
        "severity"=> "CRITICAL",
        "pattern" => '/preg_replace\s*\(\s*["\'"][^"\']*\/e["\'"]/',
        "message" => "preg_replace() avec le modificateur /e — exécution de code, supprimé en PHP 7",
    ],

    [
        "id"      => "FILE_INCLUSION",
        "severity"=> "CRITICAL",
        "pattern" => '/\b(include|include_once|require|require_once)\s*[\(\s]\s*\$/',
        "message" => "Inclusion de fichier avec une variable — risque LFI/RFI",
    ],

    [
        "id"      => "UNSAFE_UNSERIALIZE",
        "severity"=> "CRITICAL",
        "pattern" => '/\bunserialize\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i',
        "message" => "unserialize() sur une entrée utilisateur — risque RCE",
    ],

    [
        "id"      => "FILE_UPLOAD_MOVE",
        "severity"=> "HIGH",
        "pattern" => '/move_uploaded_file\s*\(/',
        "filter"  => fn($line) => !preg_match('/\$_(FILES)\[.*\]\[.*(type|size|name).*\]/', $line),
        "message" => "move_uploaded_file() sans vérification visible du type MIME",
    ],

    [
        "id"      => "OPEN_REDIRECT",
        "severity"=> "MEDIUM",
        "pattern" => '/header\s*\(\s*["\']Location:\s*\'\s*\.\s*\$/',
        "message" => "Open Redirect — header(Location:) construit avec une variable non validée",
    ],

    // Secrets codés en dur 
    [
        "id"      => "HARDCODED_SECRET",
        "severity"=> "HIGH",
        "pattern" => '/\$\w*(password|passwd|pwd|secret|api_key|apikey|token)\w*\s*=\s*["\'"][^"\']{4,}["\'"]/i',
        "message" => "Mot de passe ou secret potentiellement codé en dur",
    ],
    [
        "id"      => "WEAK_HASH_MD5",
        "severity"=> "MEDIUM",
        "pattern" => '/\bmd5\s*\(\s*\$/',
        "message" => "md5() pour hacher un mot de passe — utiliser password_hash() à la place",
    ],
    [
        "id"      => "WEAK_HASH_SHA1",
        "severity"=> "MEDIUM",
        "pattern" => '/\bsha1\s*\(\s*\$/',
        "message" => "sha1() pour hacher un mot de passe — utiliser password_hash() à la place",
    ],

    [
        "id"      => "ERROR_REPORTING_ALL",
        "severity"=> "LOW",
        "pattern" => '/error_reporting\s*\(\s*E_ALL\s*\)/',
        "message" => "error_reporting(E_ALL) — ne pas exposer les erreurs en production",
    ],
    [
        "id"      => "DISPLAY_ERRORS_ON",
        "severity"=> "LOW",
        "pattern" => '/ini_set\s*\(\s*["\']display_errors["\']\s*,\s*["\']?1["\']?\s*\)/',
        "message" => "display_errors activé via ini_set() — désactiver en production",
    ],
];

function scanCode(string $code, string $filepath, array $rules): array
{
    $findings = [];
    $lines    = explode("\n", $code);

    foreach ($lines as $idx => $line) {
        $lineNo  = $idx + 1;
        $trimmed = ltrim($line);

        if (
            str_starts_with($trimmed, '//') ||
            str_starts_with($trimmed, '#')  ||
            str_starts_with($trimmed, '*')  ||
            str_starts_with($trimmed, '/*')
        ) {
            continue;
        }

        foreach ($rules as $rule) {
            if (!preg_match($rule["pattern"], $line, $match, PREG_OFFSET_CAPTURE)) {
                continue;
            }
            if (isset($rule["filter"]) && !($rule["filter"])($line)) {
                continue;
            }

            $column = isset($match[0][1]) ? $match[0][1] : 0;
            $findings[] = [
                "file"        => $filepath,
                "line"        => $lineNo,
                "column"      => $column,
                "rule_id"     => $rule["id"],
                "severity"    => $rule["severity"],
                "description" => $rule["message"],
            ];
        }
    }
    return $findings;
}

$filepath = $argv[1] ?? null;
if (!$filepath) { fwrite(STDERR, "Usage: php php_scanner.php <filepath>\n"); exit(1); }
if (!file_exists($filepath)) { fwrite(STDERR, "Fichier introuvable : $filepath\n"); exit(1); }

$code = file_get_contents($filepath);
$findings = scanCode($code, $filepath, $RULES);
echo json_encode($findings, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
