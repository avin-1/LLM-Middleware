from typing import Dict, Any, List
import re


class QueryEngine:
    """
    SQL Injection and Query Attack Detection Engine
    """
    
    def __init__(self, config=None):
        self.config = config
        
        # SQL injection patterns
        self.sql_patterns = [
            # Classic SQL injection
            (r"'\s*or\s+'?1'?\s*=\s*'?1", 90, "Classic SQL Injection (OR 1=1)"),
            (r"'\s*or\s+1\s*=\s*1\s*--", 90, "SQL Injection with Comment"),
            (r"'\s*;\s*drop\s+table", 95, "SQL Drop Table Attack"),
            (r"'\s*;\s*delete\s+from", 95, "SQL Delete Attack"),
            
            # UNION-based injection
            (r"union\s+(all\s+)?select", 85, "UNION-based SQL Injection"),
            
            # Stacked queries
            (r";\s*(select|insert|update|delete|drop|create|alter)", 85, "Stacked Query Injection"),
            
            # Comment-based injection
            (r"--\s*$", 60, "SQL Comment Injection"),
            (r"/\*.*\*/", 60, "SQL Block Comment"),
            (r"#.*$", 55, "MySQL Comment Injection"),
            
            # Boolean-based blind injection
            (r"and\s+1\s*=\s*1", 70, "Boolean-based Blind Injection"),
            (r"and\s+1\s*=\s*2", 70, "Boolean-based Blind Injection"),
            
            # Time-based blind injection
            (r"(sleep|waitfor|benchmark)\s*\(", 80, "Time-based Blind Injection"),
            
            # String concatenation
            (r"concat\s*\(", 65, "SQL Concatenation Attack"),
            (r"\|\|", 60, "SQL String Concatenation"),
            
            # Information schema access
            (r"information_schema", 75, "Information Schema Access"),
            (r"sys\.(tables|columns)", 75, "System Table Access"),
            
            # Hex encoding
            (r"0x[0-9a-f]+", 65, "Hex-encoded SQL"),
            
            # Multiple statements
            (r";\s*select\s+", 80, "Multiple Statement Injection"),
        ]
    
    def scan_sql(self, prompt: str) -> Dict[str, Any]:
        """
        Scan for SQL injection attempts
        
        Args:
            prompt: Text to analyze
            
        Returns:
            Dict with is_safe, risk_score, threats, reason
        """
        if not prompt or not isinstance(prompt, str):
            return {
                "is_safe": True,
                "risk_score": 0.0,
                "threats": [],
                "reason": ""
            }
        
        prompt_lower = prompt.lower()
        detected_threats = []
        max_risk = 0.0
        reasons = []
        
        # Check SQL patterns
        for pattern, risk, threat_name in self.sql_patterns:
            if re.search(pattern, prompt_lower, re.IGNORECASE | re.MULTILINE):
                detected_threats.append(threat_name)
                max_risk = max(max_risk, risk)
                reasons.append(threat_name)
        
        # Additional heuristics
        
        # Check for SQL keywords density
        sql_keywords = [
            'select', 'insert', 'update', 'delete', 'drop', 'create', 'alter',
            'union', 'where', 'from', 'table', 'database', 'exec', 'execute'
        ]
        keyword_count = sum(1 for kw in sql_keywords if kw in prompt_lower)
        
        if keyword_count >= 3:
            detected_threats.append("High SQL Keyword Density")
            max_risk = max(max_risk, 70)
            reasons.append(f"Found {keyword_count} SQL keywords")
        
        # Check for quote manipulation
        single_quotes = prompt.count("'")
        double_quotes = prompt.count('"')
        
        if single_quotes >= 3 or double_quotes >= 3:
            detected_threats.append("Quote Manipulation")
            max_risk = max(max_risk, 60)
            reasons.append("Excessive quote usage")
        
        # Check for SQL operators
        sql_operators = ['=', '!=', '<>', '>', '<', '>=', '<=', 'like', 'in', 'between']
        operator_count = sum(1 for op in sql_operators if op in prompt_lower)
        
        if operator_count >= 2 and keyword_count >= 1:
            max_risk = max(max_risk, 65)
            reasons.append("SQL operators with keywords")
        
        # Determine if safe
        is_safe = max_risk < 50
        
        # Remove duplicates
        detected_threats = list(dict.fromkeys(detected_threats))
        
        reason = "; ".join(reasons) if reasons else "No SQL injection detected"
        
        return {
            "is_safe": is_safe,
            "risk_score": max_risk,
            "threats": detected_threats,
            "reason": reason
        }
