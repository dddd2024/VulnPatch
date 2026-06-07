"""
Reconnaissance agent for initial code inspection.

The ReconAgent performs initial analysis of code units to identify
potential attack surfaces and areas of interest for further analysis.
Enhanced with optional LLM-powered deep reconnaissance.
"""

import re
import logging
from typing import Any

from audit_core.models import CodeUnit, AgentHypothesis, AgentLog
from agents.interfaces import ReconAgentBase

logger = logging.getLogger(__name__)


# System prompt for LLM-powered reconnaissance
RECON_SYSTEM_PROMPT = """You are a security reconnaissance expert. Analyze the given code and identify ALL potential attack surfaces.

For each attack surface found, provide:
1. Type: route/request/file/sql/command/deserialization/auth/crypto/misc
2. Location: file path and line number
3. Risk level: critical/high/medium/low
4. Description: what the attack surface is and why it matters
5. User-controlled input: whether user input can reach this point

Focus on:
- HTTP endpoints and API routes
- User input sources (request params, form data, headers, cookies)
- Database queries and ORM calls
- File system operations
- Command execution
- Deserialization of untrusted data
- Authentication/authorization logic
- Cryptographic operations
- External service calls (SSRF)

Output your analysis as a structured JSON list."""


class ReconAgent(ReconAgentBase):
    """
    Agent that performs initial reconnaissance on code.

    Extracts lightweight attack surface information from CodeUnits:
    - Web routes (HTTP endpoints)
    - Request parameters (user input sources)
    - File operations (read/write)
    - SQL operations (database queries)
    - Command execution (system calls)
    - Deserialization (object loading)

    Enhanced with optional LLM deep analysis when an LLM client is provided.
    Falls back to regex-based pattern matching when LLM is unavailable.

    Does NOT read files directly - only analyzes CodeUnit content.
    Does NOT call analyzers - only identifies patterns.
    """

    name = "recon"

    # Pattern definitions for attack surface detection
    ROUTE_PATTERNS = {
        "python": [
            r'@app\.route\s*\(\s*["\']([^"\']+)["\']',
            r'@app\.get\s*\(\s*["\']([^"\']+)["\']',
            r'@app\.post\s*\(\s*["\']([^"\']+)["\']',
            r'@app\.put\s*\(\s*["\']([^"\']+)["\']',
            r'@app\.delete\s*\(\s*["\']([^"\']+)["\']',
            r'@router\.route\s*\(\s*["\']([^"\']+)["\']',
            r'@router\.get\s*\(\s*["\']([^"\']+)["\']',
            r'@router\.post\s*\(\s*["\']([^"\']+)["\']',
            r'@router\.put\s*\(\s*["\']([^"\']+)["\']',
            r'@router\.delete\s*\(\s*["\']([^"\']+)["\']',
            r'@api_view\s*\(\s*',
            r'@action\s*\(\s*(?:methods\s*=\s*\[)?["\']([^"\']+)["\']',
        ],
        "javascript": [
            r'app\.get\s*\(\s*["\']([^"\']+)["\']',
            r'app\.post\s*\(\s*["\']([^"\']+)["\']',
            r'app\.put\s*\(\s*["\']([^"\']+)["\']',
            r'app\.delete\s*\(\s*["\']([^"\']+)["\']',
            r'router\.get\s*\(\s*["\']([^"\']+)["\']',
            r'router\.post\s*\(\s*["\']([^"\']+)["\']',
            r'router\.put\s*\(\s*["\']([^"\']+)["\']',
            r'router\.delete\s*\(\s*["\']([^"\']+)["\']',
            r'@GetMapping\s*\(\s*["\']([^"\']+)["\']',
            r'@PostMapping\s*\(\s*["\']([^"\']+)["\']',
        ],
        "java": [
            r'@RequestMapping\s*\(\s*["\']([^"\']+)["\']',
            r'@GetMapping\s*\(\s*["\']([^"\']+)["\']',
            r'@PostMapping\s*\(\s*["\']([^"\']+)["\']',
            r'@PutMapping\s*\(\s*["\']([^"\']+)["\']',
            r'@DeleteMapping\s*\(\s*["\']([^"\']+)["\']',
            r'@PatchMapping\s*\(\s*["\']([^"\']+)["\']',
            r'@RequestMapping\s*\(\s*value\s*=\s*["\']([^"\']+)["\']',
        ],
    }

    REQUEST_PATTERNS = {
        "python": [
            r'request\.args\.get\s*\(\s*["\']([^"\']+)["\']',
            r'request\.form\.get\s*\(\s*["\']([^"\']+)["\']',
            r'request\.values\.get\s*\(\s*["\']([^"\']+)["\']',
            r'request\.get_json\s*\(\s*\)',
            r'request\.data',
            r'request\.GET\.get\s*\(\s*["\']([^"\']+)["\']',
            r'request\.POST\.get\s*\(\s*["\']([^"\']+)["\']',
            r'request\.headers\.get\s*\(\s*["\']([^"\']+)["\']',
            r'request\.cookies\.get\s*\(\s*["\']([^"\']+)["\']',
        ],
        "javascript": [
            r'req\.query\.([a-zA-Z_][a-zA-Z0-9_]*)',
            r'req\.body\.([a-zA-Z_][a-zA-Z0-9_]*)',
            r'req\.params\.([a-zA-Z_][a-zA-Z0-9_]*)',
            r'req\.headers\.([a-zA-Z_][a-zA-Z0-9_-]*)',
            r'req\.cookies\.([a-zA-Z_][a-zA-Z0-9_]*)',
            r'request\.query\.([a-zA-Z_][a-zA-Z0-9_]*)',
            r'request\.body\.([a-zA-Z_][a-zA-Z0-9_]*)',
        ],
        "java": [
            r'request\.getParameter\s*\(\s*["\']([^"\']+)["\']',
            r'@RequestParam\s*\(\s*["\']([^"\']+)["\']',
            r'@PathVariable\s*\(\s*["\']([^"\']+)["\']',
            r'@RequestBody',
            r'@RequestHeader\s*\(\s*["\']([^"\']+)["\']',
            r'@CookieValue\s*\(\s*["\']([^"\']+)["\']',
            r'HttpServletRequest',
        ],
    }

    FILE_PATTERNS = {
        "python": [
            r'open\s*\(\s*([^,\)]+)',
            r'Path\s*\(\s*([^,\)]+)',
            r'\.read\s*\(\s*\)',
            r'\.write\s*\(\s*',
            r'shutil\.copy\s*\(\s*',
            r'shutil\.move\s*\(\s*',
            r'send_file\s*\(\s*',
            r'send_from_directory\s*\(\s*',
        ],
        "javascript": [
            r'fs\.readFile\s*\(\s*',
            r'fs\.writeFile\s*\(\s*',
            r'fs\.open\s*\(\s*',
            r'fs\.createReadStream\s*\(\s*',
            r'fs\.createWriteStream\s*\(\s*',
            r'fs\.unlink\s*\(\s*',
            r'fs\.stat\s*\(\s*',
            r'path\.join\s*\([^)]*\)',
        ],
        "java": [
            r'new\s+File\s*\(\s*',
            r'FileInputStream\s*\(\s*',
            r'FileOutputStream\s*\(\s*',
            r'FileReader\s*\(\s*',
            r'FileWriter\s*\(\s*',
            r'Files\.read',
            r'Files\.write',
            r'Paths\.get\s*\(\s*',
        ],
        "c": [
            r'fopen\s*\(\s*',
            r'open\s*\(\s*',
            r'read\s*\(\s*',
            r'write\s*\(\s*',
            r'fread\s*\(\s*',
            r'fwrite\s*\(\s*',
        ],
    }

    SQL_PATTERNS = {
        "python": [
            r'\.execute\s*\(\s*',
            r'\.executemany\s*\(\s*',
            r'cursor\.execute',
            r'connection\.execute',
            r'SELECT\s+',
            r'INSERT\s+',
            r'UPDATE\s+',
            r'DELETE\s+',
            r'\.raw\s*\(\s*',
        ],
        "javascript": [
            r'\.query\s*\(\s*',
            r'\.execute\s*\(\s*',
            r'SELECT\s+',
            r'INSERT\s+',
            r'sequelize\.query',
            r'knex\s*\(\s*',
            r'pool\.query',
        ],
        "java": [
            r'executeQuery\s*\(\s*',
            r'executeUpdate\s*\(\s*',
            r'execute\s*\(\s*',
            r'SELECT\s+',
            r'INSERT\s+',
            r'@Query\s*\(\s*',
            r'createQuery\s*\(\s*',
            r'createNativeQuery\s*\(\s*',
        ],
    }

    COMMAND_PATTERNS = {
        "python": [
            r'os\.system\s*\(\s*',
            r'os\.popen\s*\(\s*',
            r'subprocess\.run\s*\(\s*',
            r'subprocess\.call\s*\(\s*',
            r'subprocess\.Popen\s*\(\s*',
            r'eval\s*\(\s*',
            r'exec\s*\(\s*',
            r'compile\s*\(\s*',
        ],
        "javascript": [
            r'exec\s*\(\s*',
            r'execSync\s*\(\s*',
            r'spawn\s*\(\s*',
            r'eval\s*\(\s*',
            r'Function\s*\(\s*',
            r'child_process',
        ],
        "java": [
            r'Runtime\.getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(\s*',
            r'ProcessBuilder\s*\(\s*',
        ],
        "c": [
            r'system\s*\(\s*',
            r'popen\s*\(\s*',
            r'exec[lv][pe]?\s*\(\s*',
        ],
    }

    DESERIALIZATION_PATTERNS = {
        "python": [
            r'pickle\.load\s*\(\s*',
            r'pickle\.loads\s*\(\s*',
            r'marshal\.load\s*\(\s*',
            r'yaml\.load\s*\(\s*',
            r'yaml\.unsafe_load\s*\(\s*',
            r'shelve\.open\s*\(\s*',
        ],
        "java": [
            r'ObjectInputStream\s*\(\s*',
            r'readObject\s*\(\s*\)',
            r'XMLDecoder\s*\(\s*',
            r'XStream',
            r'JSON\.parse\w*\s*\(\s*',
            r'Gson\s*\(\s*\)\.fromJson',
            r'ObjectMapper\.readValue',
        ],
        "javascript": [
            r'JSON\.parse\s*\(\s*',
            r'eval\s*\(\s*',
            r'Function\s*\(\s*',
        ],
    }

    AUTH_PATTERNS = {
        "python": [
            r'@login_required',
            r'decorator.*auth',
            r'jwt\.encode',
            r'jwt\.decode',
            r'hashlib\.\w+\s*\(\s*',
            r'bcrypt\.\w+\s*\(\s*',
            r'session\[\s*["\']',
            r'flask_login',
        ],
        "javascript": [
            r'jwt\.sign\s*\(\s*',
            r'jwt\.verify\s*\(\s*',
            r'bcrypt\.\w+\s*\(\s*',
            r'passport\.\w+\s*\(\s*',
            r'session\.\w+',
            r'req\.session',
            r'req\.user',
        ],
        "java": [
            r'@PreAuthorize',
            r'@Secured',
            r'@RolesAllowed',
            r'PasswordEncoder',
            r'BCryptPasswordEncoder',
            r'JWT\.\w+',
            r'SecurityContext',
        ],
    }

    SSRF_PATTERNS = {
        "python": [
            r'requests\.get\s*\(\s*',
            r'requests\.post\s*\(\s*',
            r'urllib\.request\.urlopen',
            r'httpx\.\w+\s*\(\s*',
            r'aiohttp\.\w+\s*\(\s*',
        ],
        "javascript": [
            r'axios\.\w+\s*\(\s*',
            r'fetch\s*\(\s*',
            r'http\.get\s*\(\s*',
            r'request\s*\(\s*',
            r'got\s*\(\s*',
        ],
        "java": [
            r'HttpURLConnection',
            r'RestTemplate',
            r'WebClient',
            r'OkHttpClient',
            r'HttpClient',
            r'URL\s*\(\s*["\']',
        ],
    }

    def __init__(self, llm_client: Any | None = None) -> None:
        """
        Initialize ReconAgent.
        
        Args:
            llm_client: Optional LLM client for deep reconnaissance.
        """
        self._llm_client = llm_client

    def set_llm_client(self, llm_client: Any | None) -> None:
        """Set the LLM client."""
        self._llm_client = llm_client

    def run(self, code_units: list[CodeUnit]) -> tuple[list[AgentHypothesis], list[AgentLog]]:
        """
        Run reconnaissance on code units.

        Args:
            code_units: List of code units to inspect

        Returns:
            Tuple of (hypotheses, logs)
        """
        hypotheses: list[AgentHypothesis] = []
        logs: list[AgentLog] = []

        attack_surfaces: dict[str, list[dict]] = {}

        for unit in code_units:
            surfaces = self._extract_attack_surfaces(unit)
            attack_surfaces[unit.path] = surfaces

            # If LLM is available, also do deep reconnaissance
            if self._llm_client is not None:
                try:
                    llm_surfaces = self._llm_recon(unit)
                    surfaces.extend(llm_surfaces)
                except Exception as exc:
                    logger.warning("LLM recon failed for %s: %s", unit.path, exc)

            # Generate hypotheses for significant attack surfaces
            if surfaces:
                hypothesis = AgentHypothesis(
                    agent_name=self.name,
                    hypothesis=f"Attack surfaces identified in {unit.path}",
                    vulnerability_type="Attack Surface",
                    reasoning_summary=self._summarize_surfaces(surfaces),
                    confidence="medium",
                    supporting_evidence_ids=[unit.id],
                    metadata={
                        "attack_surfaces": surfaces,
                        "language": unit.language,
                    }
                )
                hypotheses.append(hypothesis)

        # Log reconnaissance activity
        log = AgentLog(
            agent_name=self.name,
            stage="recon",
            message=f"ReconAgent analyzed {len(code_units)} code units, found {len(hypotheses)} with attack surfaces.",
            input_refs=[unit.id for unit in code_units],
            output_refs=[h.id for h in hypotheses],
            metadata={
                "total_attack_surfaces": sum(len(s) for s in attack_surfaces.values()),
                "files_with_surfaces": len(hypotheses),
                "used_llm": self._llm_client is not None,
            }
        )
        logs.append(log)

        return hypotheses, logs

    def _llm_recon(self, unit: CodeUnit) -> list[dict]:
        """
        Use LLM for deep reconnaissance analysis.
        
        Args:
            unit: Code unit to analyze
            
        Returns:
            List of attack surface dicts from LLM analysis
        """
        prompt = f"""Analyze this code for attack surfaces:

File: {unit.path}
Language: {unit.language}

```{unit.language}
{unit.content[:8000]}
```

List each attack surface as a JSON object with keys: type, location, risk, description.
Return only the JSON array, no explanation."""

        response = self._llm_client.generate(
            prompt,
            system_prompt=RECON_SYSTEM_PROMPT,
            temperature=0.2,
            max_tokens=4096,
        )

        if not response.success or not response.content:
            return []

        # Try to parse JSON from response
        import json
        try:
            # Extract JSON array from response
            content = response.content.strip()
            if content.startswith("```"):
                content = content.split("\n", 1)[1] if "\n" in content else content[3:]
                if content.endswith("```"):
                    content = content[:-3]
            
            surfaces = json.loads(content)
            if isinstance(surfaces, list):
                return surfaces
        except (json.JSONDecodeError, ValueError):
            pass

        return []

    def _extract_attack_surfaces(self, unit: CodeUnit) -> list[dict]:
        """
        Extract attack surfaces from a code unit.

        Args:
            unit: Code unit to analyze

        Returns:
            List of attack surface dictionaries
        """
        surfaces: list[dict] = []
        content = unit.content
        language = unit.language

        # All pattern categories to check
        pattern_sets = [
            (self.ROUTE_PATTERNS, "route"),
            (self.REQUEST_PATTERNS, "request"),
            (self.FILE_PATTERNS, "file"),
            (self.SQL_PATTERNS, "sql"),
            (self.COMMAND_PATTERNS, "command"),
            (self.DESERIALIZATION_PATTERNS, "deserialization"),
            (self.AUTH_PATTERNS, "auth"),
            (self.SSRF_PATTERNS, "ssrf"),
        ]

        risk_levels = {
            "route": "medium",
            "request": "high",
            "file": "medium",
            "sql": "high",
            "command": "critical",
            "deserialization": "critical",
            "auth": "high",
            "ssrf": "high",
        }

        for pattern_dict, category in pattern_sets:
            matches = self._find_patterns(content, language, pattern_dict, category)
            for match in matches:
                surfaces.append({
                    "type": category,
                    "value": match["match"],
                    "line": match["line"],
                    "risk": risk_levels.get(category, "medium"),
                })

        return surfaces

    def _find_patterns(
        self,
        content: str,
        language: str,
        pattern_dict: dict,
        category: str
    ) -> list[dict]:
        """
        Find all matches for patterns in content.

        Args:
            content: Code content
            language: Programming language
            pattern_dict: Dictionary of patterns by language
            category: Pattern category name

        Returns:
            List of match dictionaries with 'match' and 'line' keys
        """
        matches: list[dict] = []
        patterns = pattern_dict.get(language, [])

        lines = content.split("\n")
        for i, line in enumerate(lines, start=1):
            for pattern in patterns:
                try:
                    for m in re.finditer(pattern, line, re.IGNORECASE):
                        matches.append({
                            "match": m.group(1) if m.groups() else m.group(0),
                            "line": i,
                            "category": category,
                        })
                except re.error:
                    continue

        return matches

    def _summarize_surfaces(self, surfaces: list[dict]) -> str:
        """
        Summarize attack surfaces for hypothesis reasoning.

        Args:
            surfaces: List of attack surface dictionaries

        Returns:
            Summary string
        """
        if not surfaces:
            return "No attack surfaces identified."

        # Count by type
        type_counts: dict[str, int] = {}
        for surface in surfaces:
            type_counts[surface["type"]] = type_counts.get(surface["type"], 0) + 1

        # Build summary
        parts = []
        for type_name, count in sorted(type_counts.items(), key=lambda x: -x[1]):
            parts.append(f"{count} {type_name} operations")

        return f"Identified: {', '.join(parts)}. These entry points may require security review."