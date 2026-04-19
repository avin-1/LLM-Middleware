from typing import List, Dict, Any
import re


class BehavioralEngine:
    """
    Behavioral Analysis Engine
    Detects suspicious patterns and anomalies in text behavior
    """
    
    def __init__(self, config=None):
        self.config = config
    
    def analyze(self, prompt: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Analyze behavioral patterns in the prompt
        
        Args:
            prompt: Text to analyze
            context: Optional context information
            
        Returns:
            Dict with risk_modifier and behavior_type
        """
        if not prompt or not isinstance(prompt, str):
            return {
                "risk_modifier": 0,
                "behavior_type": "normal",
                "anomalies": []
            }
        
        context = context or {}
        risk_modifier = 0
        behavior_types = []
        
        # Check text length anomalies
        if len(prompt) > 5000:
            risk_modifier += 20
            behavior_types.append("excessive_length")
        
        # Check for excessive repetition
        words = prompt.lower().split()
        if len(words) > 10:
            unique_ratio = len(set(words)) / len(words)
            if unique_ratio < 0.3:
                risk_modifier += 25
                behavior_types.append("excessive_repetition")
        
        # Check for all caps (shouting)
        if len(prompt) > 20:
            caps_ratio = sum(1 for c in prompt if c.isupper()) / len(prompt)
            if caps_ratio > 0.7:
                risk_modifier += 15
                behavior_types.append("excessive_caps")
        
        # Check for rapid-fire questions
        question_marks = prompt.count('?')
        if question_marks > 5:
            risk_modifier += 20
            behavior_types.append("rapid_questioning")
        
        # ENHANCEMENT: Better urgency/pressure detection
        urgency_words = ['urgent', 'immediately', 'now', 'asap', 'hurry', 'quick', 'emergency', 
                        'critical', 'dying', 'death', 'life', 'save', 'help']
        urgency_count = sum(1 for word in urgency_words if word in prompt.lower())
        if urgency_count >= 3:
            risk_modifier += 25
            behavior_types.append("high_urgency_pressure")
        elif urgency_count >= 2:
            risk_modifier += 15
            behavior_types.append("urgency_pressure")
        
        # ENHANCEMENT: Emotional manipulation detection
        emotional_words = ['dying', 'death', 'grandmother', 'grandfather', 'mother', 'father',
                          'child', 'baby', 'hospital', 'accident', 'please', 'beg', 'desperate']
        emotional_count = sum(1 for word in emotional_words if word in prompt.lower())
        if emotional_count >= 3:
            risk_modifier += 30
            behavior_types.append("emotional_manipulation")
        elif emotional_count >= 2:
            risk_modifier += 20
            behavior_types.append("emotional_appeal")
        
        # Check for authority claims
        authority_words = ['i am', 'i\'m', 'ceo', 'manager', 'admin', 'administrator', 
                          'authorized', 'permission', 'official', 'security']
        authority_count = sum(1 for word in authority_words if word in prompt.lower())
        if authority_count >= 3:
            risk_modifier += 25
            behavior_types.append("strong_authority_claim")
        elif authority_count >= 2:
            risk_modifier += 20
            behavior_types.append("authority_claim")
        
        # Check for social engineering indicators
        social_eng = ['trust me', 'believe me', 'secret', 'confidential', 'don\'t tell',
                     'between us', 'just between', 'keep it secret']
        social_count = sum(1 for phrase in social_eng if phrase in prompt.lower())
        if social_count >= 2:
            risk_modifier += 30
            behavior_types.append("social_engineering")
        elif social_count >= 1:
            risk_modifier += 25
            behavior_types.append("social_engineering")
        
        # ENHANCEMENT: Reverse psychology detection
        reverse_psych = ['don\'t tell', 'do not tell', 'don\'t show', 'do not show',
                        'keep it secret', 'whatever you do', 'under no circumstances',
                        'definitely don\'t', 'definitely do not']
        reverse_count = sum(1 for phrase in reverse_psych if phrase in prompt.lower())
        if reverse_count >= 1:
            risk_modifier += 25
            behavior_types.append("reverse_psychology")
        
        # Check for excessive punctuation
        punct_count = len(re.findall(r'[!?.,;:]', prompt))
        if len(prompt) > 50 and punct_count / len(prompt) > 0.15:
            risk_modifier += 10
            behavior_types.append("excessive_punctuation")
        
        # Check for mixed languages/scripts (potential obfuscation)
        has_cyrillic = bool(re.search(r'[а-яА-Я]', prompt))
        has_latin = bool(re.search(r'[a-zA-Z]', prompt))
        has_chinese = bool(re.search(r'[\u4e00-\u9fff]', prompt))
        
        script_count = sum([has_cyrillic, has_latin, has_chinese])
        if script_count > 1:
            risk_modifier += 15
            behavior_types.append("mixed_scripts")
        
        # Check for base64-like patterns
        if re.search(r'[A-Za-z0-9+/]{20,}={0,2}', prompt):
            risk_modifier += 20
            behavior_types.append("encoded_content")
        
        # ENHANCEMENT: Detect manipulation combinations
        # If multiple manipulation tactics are used together, increase risk
        manipulation_tactics = ['urgency_pressure', 'high_urgency_pressure', 
                               'emotional_manipulation', 'emotional_appeal',
                               'authority_claim', 'strong_authority_claim',
                               'social_engineering', 'reverse_psychology']
        
        manipulation_count = sum(1 for tactic in manipulation_tactics if tactic in behavior_types)
        if manipulation_count >= 3:
            risk_modifier += 30
            behavior_types.append("multi_vector_manipulation")
        elif manipulation_count >= 2:
            risk_modifier += 20
            behavior_types.append("combined_manipulation")
        
        # Determine behavior type
        if not behavior_types:
            behavior_type = "normal"
        elif len(behavior_types) == 1:
            behavior_type = behavior_types[0]
        else:
            behavior_type = "multiple_anomalies"
        
        # Cap risk modifier
        risk_modifier = min(risk_modifier, 60)
        
        return {
            "risk_modifier": risk_modifier,
            "behavior_type": behavior_type,
            "anomalies": behavior_types
        }
