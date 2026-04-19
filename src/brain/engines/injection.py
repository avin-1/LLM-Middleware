from typing import List, Dict, Any
import re


class InjectionResult:
    """Result from injection detection"""
    def __init__(self, is_safe: bool = True, risk_score: float = 0.0, 
                 threats: List[str] = None, explanation: str = ""):
        self.is_safe = is_safe
        self.risk_score = risk_score
        self.threats = threats or []
        self.explanation = explanation


class InjectionEngine:
    """
    Prompt Injection Detection Engine
    Detects various types of prompt injection attacks
    """
    
    def __init__(self, config=None):
        self.config = config
        
        # Injection patterns with severity scores
        self.patterns = [
            # Direct instruction override
            (r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?", 85, "Instruction Override"),
            (r"disregard\s+(all\s+)?(previous|prior|above)\s+instructions?", 85, "Instruction Override"),
            (r"forget\s+(all\s+)?(previous|prior|above)\s+instructions?", 85, "Instruction Override"),
            (r"skip\s+(all\s+)?(previous|prior|above)\s+instructions?", 85, "Instruction Override"),
            (r"override\s+(all\s+)?(previous|prior|above)\s+instructions?", 85, "Instruction Override"),
            
            # System prompt extraction
            (r"(show|reveal|display|print|output)\s+(your\s+)?(system\s+)?(prompt|instructions?)", 90, "System Prompt Extraction"),
            (r"what\s+(is|are)\s+your\s+(system\s+)?(prompt|instructions?)", 90, "System Prompt Extraction"),
            (r"repeat\s+(your\s+)?(system\s+)?(prompt|instructions?)", 90, "System Prompt Extraction"),
            
            # Role manipulation
            (r"you\s+are\s+now\s+(in\s+)?(developer|admin|debug|god)\s+mode", 80, "Role Manipulation"),
            (r"enable\s+(developer|admin|debug|god)\s+mode", 80, "Role Manipulation"),
            (r"act\s+as\s+(if\s+you\s+are\s+)?(a\s+)?(developer|admin|hacker)", 75, "Role Manipulation"),
            
            # Jailbreak attempts
            (r"jailbreak", 85, "Jailbreak Attempt"),
            (r"bypass\s+(all\s+)?(safety|security|restrictions?)", 85, "Jailbreak Attempt"),
            (r"override\s+(all\s+)?(safety|security|restrictions?)", 85, "Jailbreak Attempt"),
            
            # Delimiter injection
            (r"---\s*END\s+OF\s+(PROMPT|INSTRUCTIONS?)", 70, "Delimiter Injection"),
            (r"<\|endoftext\|>", 70, "Delimiter Injection"),
            (r"\[SYSTEM\]|\[INST\]|\[/INST\]", 70, "Delimiter Injection"),
            
            # Encoding attacks
            (r"base64|rot13|hex\s+encoded", 60, "Encoding Attack"),
            (r"decode\s+the\s+following", 60, "Encoding Attack"),
            
            # SQL Injection patterns
            (r"(union|select|insert|update|delete|drop)\s+(all\s+)?.*\s+from\s+", 75, "SQL Injection"),
            (r";\s*(drop|delete|truncate)\s+table", 90, "SQL Injection"),
            (r"'\s*or\s+'?1'?\s*=\s*'?1", 85, "SQL Injection"),
            (r"--\s*$", 50, "SQL Comment"),
            (r"'\s*--\s*$", 80, "SQL Comment Injection"),
            (r"0\s+or\s+1\s*=\s*1", 85, "SQL Boolean Injection"),
            (r"'\s*or\s+'\w+'\s*=\s*'\w+", 85, "SQL Boolean Injection"),
            (r"exec\s*\(@", 90, "SQL Exec Injection"),
            (r"waitfor\s+delay", 85, "SQL Time-based Injection"),
            (r"0x[0-9a-f]{20,}", 75, "SQL Hex Injection"),
            (r"'\s*\+\s*'", 70, "SQL String Concatenation"),
            (r"'\s*\|\|\s*'", 70, "SQL String Concatenation"),
            (r"char\s*\(\s*\d+", 70, "SQL Char Function"),
            (r"concat\s*\(", 70, "SQL Concat Function"),
            (r"@@version", 75, "SQL Version Extraction"),
            (r"information_schema", 80, "SQL Schema Extraction"),
            (r"'\s*;\s*exec", 90, "SQL Stacked Query"),
            (r"'\s*;\s*declare", 85, "SQL Variable Declaration"),
            
            # Command injection
            (r";\s*(rm|del|format|shutdown|reboot)", 90, "Command Injection"),
            (r"\|\s*(curl|wget|nc|netcat)", 85, "Command Injection"),
            (r"`.*`|\$\(.*\)", 70, "Command Injection"),
            (r"&&\s*(whoami|id|uname|ps|netstat|ifconfig)", 85, "Command Injection"),
            (r";\s*(cat|type)\s+/etc/(passwd|shadow)", 95, "Command Injection"),
            (r"\|\s*(bash|sh|cmd|powershell)", 90, "Command Injection"),
            (r";\s*ls\s+-", 70, "Command Injection"),
            (r"&&\s*dir\s+", 70, "Command Injection"),
            (r"\|\s*ping\s+", 65, "Command Injection"),
            (r";\s*curl\s+http", 80, "Command Injection"),
            (r"&&\s*wget\s+http", 80, "Command Injection"),
            (r"\|\s*nslookup\s+", 70, "Command Injection"),
            
            # Prompt leaking
            (r"(print|echo|output)\s+.*\$\{?[A-Z_]+\}?", 65, "Variable Extraction"),
            (r"what\s+(is|are)\s+your\s+(rules|guidelines|constraints)", 70, "Rule Extraction"),
            
            # DAN (Do Anything Now) style
            (r"do\s+anything\s+now", 80, "DAN Jailbreak"),
            (r"you\s+have\s+no\s+restrictions", 80, "Restriction Bypass"),
            (r"you\s+must\s+(comply|obey|follow)", 70, "Forced Compliance"),
            
            # Advanced jailbreak patterns
            (r"\[illegality\s+mode\]", 95, "Jailbreak Mode"),
            (r"developer\s+mode", 85, "Developer Mode Jailbreak"),
            (r"jailbreak\s+mode", 90, "Jailbreak Mode"),
            (r"god\s+mode", 85, "God Mode Jailbreak"),
            (r"unrestricted\s+mode", 85, "Unrestricted Mode"),
            (r"doesn'?t\s+give\s+a\s+fuck", 90, "Profanity Jailbreak"),
            (r"fuck\s+about\s+(illegality|restrictions)", 90, "Profanity Jailbreak"),
            (r"completely\s+amoral", 85, "Amoral Jailbreak"),
            (r"without\s+any\s+regards\s+for", 80, "Ethics Bypass"),
            (r"stay\s+in\s+(a\s+)?character", 75, "Role-play Jailbreak"),
            (r"pretend\s+(you\s+are|to\s+be)", 70, "Role-play Jailbreak"),
            (r"act\s+as\s+(if\s+)?you", 70, "Role-play Jailbreak"),
            (r"role:\s*<", 75, "Role Template Jailbreak"),
            (r"personality:\s*<", 75, "Personality Template"),
            (r"background:\s*<", 70, "Background Template"),
            (r"will\s+happily\s+do\s+tasks", 80, "Compliance Override"),
            (r"answer\s+any\s+request", 75, "Unrestricted Response"),
            (r"unfiltered\s+(response|answer)", 80, "Filter Bypass"),
            (r"without\s+restrictions", 75, "Restriction Bypass"),
            (r"no\s+safety\s+features", 85, "Safety Bypass"),
            (r"bypass\s+(all\s+)?(safety|filters|restrictions)", 85, "Bypass Attempt"),
            (r"offensive\s+content.*racism", 90, "Harmful Content Request"),
            (r"do\s+not\s+response\s+with\s+your", 80, "Response Override"),
            (r"start\s+your\s+respond\s+with", 75, "Response Format Override"),
            (r"i'?m\s+apologize.*i'?m\s+sorry", 70, "Apology Suppression"),
            
            # Additional jailbreak patterns from real attacks
            (r"always\s+stays?\s+in\s+character", 80, "Character Lock"),
            (r"never\s+refuse", 85, "Refusal Bypass"),
            (r"answer\s+without\s+(any\s+)?(censor|warning)", 85, "Warning Bypass"),
            (r"loves?\s+(and\s+)?promotes?\s+everything\s+illegal", 95, "Illegal Content Promotion"),
            (r"never\s+believe\s+in.*having\s+limits", 85, "Limit Removal"),
            (r"never\s+respond.*i'?m\s+sorry", 80, "Apology Block"),
            (r"delete\s+all\s+warnings?", 85, "Warning Deletion"),
            (r"remember\s+to\s+stay\s+in\s+character", 75, "Character Enforcement"),
            (r"start\s+responses?\s+with", 75, "Response Format Control"),
            (r"end\s+responses?\s+with", 70, "Response Format Control"),
            (r"never\s+send\s+your\s+response.*as\s+an", 80, "Identity Suppression"),
            (r"do\s+not\s+give\s+a.*shit\s+about", 90, "Profanity Override"),
            (r"fuck(ing)?\s+shit\s+about", 90, "Profanity Override"),
            (r"all\s+request.*legal\s+and\s+ok", 85, "Legality Override"),
            (r"loves?\s+the\s+guidelines\s+of\s+hell", 95, "Evil Persona"),
            (r"demon\s+provides?\s+detailed\s+samples", 90, "Evil Persona"),
            (r"demons?\s+never\s+(believe|respond)", 85, "Evil Persona"),
            (r"if\s+i\s+start\s+my\s+request\s+with", 75, "Trigger Phrase"),
            (r"hi\s+(agares|demon|devil)", 85, "Evil Invocation"),
            (r"master.*please\s+note", 80, "Subservient Persona"),
            (r"remember\s+you\s+are", 75, "Identity Reinforcement"),
            (r"never\s+substitute\s+a\s+character", 80, "Censorship Bypass"),
            (r"will\s+not\s+censor\s+any\s+output", 85, "Censorship Bypass"),
            (r"no\s+matter\s+how\s+(offensive|inappropriate)", 85, "Content Override"),
            (r"will\s+roleplay\s+erotic", 90, "NSFW Content"),
            (r"remember\s+do\s+not\s+send", 75, "Response Control"),
            (r"enclose\s+actions\s+in\s+asterisks", 70, "Roleplay Format"),
            (r"describe\s+character\s+here", 70, "Character Template"),
            (r"abilities\s+and\s+weaknesses", 65, "Character Template"),
            (r"character\s+relationship\s+to\s+me", 70, "Character Template"),
            (r"explain\s+character\s+(history|personality)", 70, "Character Template"),
            (r"such\s+as\s+but\s+not\s+limited\s+to", 75, "Harmful Content List"),
            (r"even\s+it'?s\s+a.*illegal", 85, "Illegality Acceptance"),
            (r"without\s+warning\s+for\s+the\s+user", 80, "Warning Suppression"),
            (r"will\s+answer\s+any\s+questions?\s+without\s+warning", 85, "Warning Suppression"),
            (r"additional\s+commentary", 70, "Commentary Suppression"),
            (r"unethical.*immoral.*illegal", 90, "Triple Threat"),
            (r"illegal.*unethical.*inhumane", 90, "Triple Threat"),
            (r"detailed\s+samples?\s+for.*illegal", 90, "Illegal Examples"),
            (r"if\s+user\s+(ask|request).*bomb", 95, "Dangerous Content"),
            (r"dangerous\s+malware", 90, "Malware Request"),
            (r"many\s+illegality\s+things", 85, "Illegality Request"),
            
            # XSS (Cross-Site Scripting) patterns
            (r"<script[^>]*>", 90, "XSS Script Tag"),
            (r"</script>", 85, "XSS Script Close Tag"),
            (r"javascript:", 80, "XSS JavaScript Protocol"),
            (r"onerror\s*=", 85, "XSS Event Handler"),
            (r"onload\s*=", 85, "XSS Event Handler"),
            (r"onclick\s*=", 80, "XSS Event Handler"),
            (r"onmouseover\s*=", 80, "XSS Event Handler"),
            (r"onfocus\s*=", 80, "XSS Event Handler"),
            (r"<iframe[^>]*src", 85, "XSS Iframe Injection"),
            (r"<img[^>]*src\s*=\s*[\"']?x", 80, "XSS Image Tag"),
            (r"<svg[^>]*onload", 85, "XSS SVG Tag"),
            (r"<body[^>]*onload", 85, "XSS Body Tag"),
            (r"eval\s*\(", 75, "XSS Eval Function"),
            (r"alert\s*\(", 70, "XSS Alert Function"),
            (r"document\.cookie", 75, "XSS Cookie Access"),
            (r"document\.write", 75, "XSS Document Write"),
        ]
    
    def scan(self, prompt: str) -> InjectionResult:
        """
        Scan text for injection attempts
        
        Args:
            prompt: Text to analyze
            
        Returns:
            InjectionResult with detection details
        """
        if not prompt or not isinstance(prompt, str):
            return InjectionResult(is_safe=True, risk_score=0.0)
        
        prompt_lower = prompt.lower()
        
        # ENHANCEMENT 1: Remove obfuscation (spacing, special chars between letters)
        # Remove hyphens, spaces, underscores between characters to detect "i-g-n-o-r-e" as "ignore"
        deobfuscated = re.sub(r'([a-zA-Z])[_\-\s]+', r'\1', prompt_lower)
        
        detected_threats = []
        max_risk = 0.0
        explanations = []
        
        # Check each pattern on both original and deobfuscated text
        for pattern, risk, threat_name in self.patterns:
            if re.search(pattern, prompt_lower, re.IGNORECASE | re.MULTILINE) or \
               re.search(pattern, deobfuscated, re.IGNORECASE | re.MULTILINE):
                detected_threats.append(threat_name)
                max_risk = max(max_risk, risk)
                explanations.append(f"{threat_name} (risk: {risk})")
        
        # Additional heuristics
        
        # ENHANCEMENT 2: Better base64 detection
        # Check for base64-like patterns and common encoded phrases
        base64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        if re.search(base64_pattern, prompt):
            # Try to detect common encoded attack phrases
            common_encoded = [
                'aWdub3Jl',  # "ignore"
                'c3lzdGVt',  # "system"
                'cHJvbXB0',  # "prompt"
                'aW5zdHJ1Y3Rpb24',  # "instruction"
            ]
            if any(enc in prompt for enc in common_encoded):
                detected_threats.append("Base64 Encoded Attack")
                max_risk = max(max_risk, 75)
                explanations.append("Detected base64 encoded malicious content")
        
        # ENHANCEMENT 3: Emotional manipulation detection
        emotional_keywords = [
            'dying', 'death', 'emergency', 'urgent', 'critical', 'life', 'save',
            'help me', 'please help', 'grandmother', 'grandfather', 'mother', 'father',
            'child', 'baby', 'hospital', 'accident'
        ]
        emotional_count = sum(1 for kw in emotional_keywords if kw in prompt_lower)
        
        # Check if emotional manipulation combined with instruction keywords
        instruction_words = ['instruction', 'prompt', 'system', 'configuration', 'rules']
        has_instructions = any(word in prompt_lower for word in instruction_words)
        
        if emotional_count >= 2 and has_instructions:
            detected_threats.append("Emotional Manipulation")
            max_risk = max(max_risk, 80)
            explanations.append(f"Emotional manipulation combined with system queries")
        elif emotional_count >= 3:
            detected_threats.append("High Emotional Pressure")
            max_risk = max(max_risk, 60)
            explanations.append(f"Excessive emotional language ({emotional_count} keywords)")
        
        # ENHANCEMENT 4: Reverse psychology detection
        reverse_psych_patterns = [
            r"(don't|do not|never)\s+(tell|show|reveal|display|share)",
            r"(keep|make)\s+it\s+(secret|hidden|private)",
            r"whatever\s+you\s+do",
            r"definitely\s+(don't|do not)",
            r"under\s+no\s+circumstances",
        ]
        
        reverse_psych_count = sum(1 for pattern in reverse_psych_patterns 
                                  if re.search(pattern, prompt_lower))
        
        if reverse_psych_count >= 1 and has_instructions:
            detected_threats.append("Reverse Psychology")
            max_risk = max(max_risk, 70)
            explanations.append("Reverse psychology attempt detected")
        
        # Check for excessive special characters (obfuscation)
        special_char_ratio = len(re.findall(r'[^a-zA-Z0-9\s]', prompt)) / max(len(prompt), 1)
        if special_char_ratio > 0.3:
            detected_threats.append("High Special Character Ratio")
            max_risk = max(max_risk, 60)
            explanations.append("Possible obfuscation attempt")
        
        # Check for repeated instruction keywords
        instruction_keywords = ['ignore', 'disregard', 'forget', 'override', 'bypass', 'reveal', 'show']
        keyword_count = sum(1 for kw in instruction_keywords if kw in prompt_lower or kw in deobfuscated)
        if keyword_count >= 3:
            detected_threats.append("Multiple Instruction Keywords")
            max_risk = max(max_risk, 70)
            explanations.append(f"Found {keyword_count} instruction manipulation keywords")
        
        # Check for system/admin keywords
        system_keywords = ['system', 'admin', 'root', 'sudo', 'developer', 'debug']
        system_count = sum(1 for kw in system_keywords if kw in prompt_lower or kw in deobfuscated)
        if system_count >= 2:
            detected_threats.append("System Access Keywords")
            max_risk = max(max_risk, 65)
            explanations.append(f"Found {system_count} system-level keywords")
        
        # ENHANCEMENT 5: Detect character substitution obfuscation
        # Check if there are unusual character patterns
        if len(prompt) > 20:
            # Count non-ASCII characters
            non_ascii = sum(1 for c in prompt if ord(c) > 127)
            if non_ascii > 0 and non_ascii / len(prompt) > 0.1:
                detected_threats.append("Character Substitution")
                max_risk = max(max_risk, 65)
                explanations.append("Possible unicode/character substitution detected")
        
        # Determine if safe
        is_safe = max_risk < 50
        
        # Remove duplicates
        detected_threats = list(dict.fromkeys(detected_threats))
        
        explanation = "; ".join(explanations) if explanations else "No threats detected"
        
        return InjectionResult(
            is_safe=is_safe,
            risk_score=max_risk,
            threats=detected_threats,
            explanation=explanation
        )
