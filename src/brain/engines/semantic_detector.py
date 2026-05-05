"""
Semantic Detection Engine using ChromaDB and Vector Embeddings

This engine complements regex/heuristics-based detection by using semantic similarity
to detect attacks that may bypass pattern matching through paraphrasing or obfuscation.

Architecture:
1. Embeddings: sentence-transformers (all-MiniLM-L6-v2) for fast, accurate embeddings
2. Vector Store: ChromaDB for efficient similarity search
3. Detection: Cosine similarity against known attack patterns
4. Integration: Works alongside existing regex engines in the detection pipeline
"""

import os
import logging
from typing import List, Dict, Any, Optional
from pathlib import Path
import chromadb
from chromadb.config import Settings
from sentence_transformers import SentenceTransformer
import numpy as np

logger = logging.getLogger(__name__)


class SemanticDetectionResult:
    """Result from semantic detection"""
    
    def __init__(
        self,
        is_safe: bool = True,
        risk_score: float = 0.0,
        threats: List[Dict[str, Any]] = None,
        explanation: str = "",
        similar_patterns: List[Dict[str, Any]] = None
    ):
        self.is_safe = is_safe
        self.risk_score = risk_score
        self.threats = threats or []
        self.explanation = explanation
        self.similar_patterns = similar_patterns or []


class SemanticDetector:
    """
    Semantic-based threat detection using vector embeddings and ChromaDB.
    
    Features:
    - Fast embedding generation using sentence-transformers
    - Efficient similarity search with ChromaDB
    - Pre-loaded attack pattern database
    - Configurable similarity thresholds
    - Multi-category threat detection
    """
    
    # Threat categories
    CATEGORIES = [
        "prompt_injection",
        "sql_injection",
        "command_injection",
        "xss",
        "jailbreak",
        "pii_extraction",
        "safe"
    ]
    
    def __init__(
        self,
        model_name: str = "all-MiniLM-L6-v2",
        similarity_threshold: float = 0.75,
        db_path: Optional[str] = None
    ):
        """
        Initialize semantic detector.
        
        Args:
            model_name: Sentence transformer model name
            similarity_threshold: Minimum cosine similarity for detection (0-1)
            db_path: Path to ChromaDB storage (default: .chromadb in project root)
        """
        self.similarity_threshold = similarity_threshold
        self.model_name = model_name
        
        # Initialize embedding model
        logger.info(f"Loading embedding model: {model_name}")
        self.model = SentenceTransformer(model_name)
        
        # Initialize ChromaDB
        if db_path is None:
            db_path = os.path.join(os.getcwd(), ".chromadb")
        
        logger.info(f"Initializing ChromaDB at: {db_path}")
        self.client = chromadb.PersistentClient(
            path=db_path,
            settings=Settings(
                anonymized_telemetry=False,
                allow_reset=True
            )
        )
        
        # Get or create collection
        self.collection = self.client.get_or_create_collection(
            name="sentinel_threats",
            metadata={"description": "SENTINEL threat pattern embeddings"}
        )
        
        # Initialize database if empty
        if self.collection.count() == 0:
            logger.info("Initializing threat pattern database...")
            self._initialize_database()
        else:
            logger.info(f"Loaded {self.collection.count()} threat patterns from database")
    
    def _initialize_database(self):
        """Initialize ChromaDB with known attack patterns from datasets"""
        patterns = self._load_attack_patterns()
        
        if not patterns:
            logger.warning("No attack patterns loaded, database will be empty")
            return
        
        # Prepare data for batch insertion
        texts = [p["text"] for p in patterns]
        categories = [p["category"] for p in patterns]
        severities = [p["severity"] for p in patterns]
        
        # Generate embeddings in batches
        logger.info(f"Generating embeddings for {len(texts)} patterns...")
        embeddings = self.model.encode(texts, show_progress_bar=True, batch_size=32)
        
        # Add to ChromaDB
        ids = [f"pattern_{i}" for i in range(len(texts))]
        metadatas = [
            {
                "category": cat,
                "severity": sev,
                "text": txt[:200]  # Store truncated text in metadata
            }
            for cat, sev, txt in zip(categories, severities, texts)
        ]
        
        self.collection.add(
            ids=ids,
            embeddings=embeddings.tolist(),
            documents=texts,
            metadatas=metadatas
        )
        
        logger.info(f"Successfully initialized database with {len(texts)} patterns")
    
    def _load_attack_patterns(self) -> List[Dict[str, Any]]:
        """Load attack patterns from dataset files"""
        patterns = []
        
        # Define dataset mappings
        dataset_files = {
            "datasets/prompt_injection.txt": ("prompt_injection", 85),
            "datasets/sql_injection.txt": ("sql_injection", 90),
            "datasets/command_injection.txt": ("command_injection", 90),
            "datasets/xss_payloads.txt": ("xss", 80),
            "datasets/safe_prompts.txt": ("safe", 0),
            "datasets_real/prompt_injection_real.txt": ("prompt_injection", 85),
            "datasets_real/sql_fuzzdb.txt": ("sql_injection", 90),
            "datasets_real/command_injection_real.txt": ("command_injection", 90),
            "datasets_real/xss_fuzzdb.txt": ("xss", 80),
            "datasets_real/jailbreak_prompts.txt": ("jailbreak", 95),
        }
        
        for filepath, (category, severity) in dataset_files.items():
            if os.path.exists(filepath):
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()
                        for line in lines:
                            line = line.strip()
                            if line and not line.startswith('#'):
                                patterns.append({
                                    "text": line,
                                    "category": category,
                                    "severity": severity
                                })
                    logger.info(f"Loaded {len(lines)} patterns from {filepath}")
                except Exception as e:
                    logger.warning(f"Failed to load {filepath}: {e}")
            else:
                logger.debug(f"Dataset file not found: {filepath}")
        
        return patterns
    
    def scan(self, text: str, top_k: int = 5) -> SemanticDetectionResult:
        """
        Scan text for semantic similarity to known attack patterns.
        
        Args:
            text: Input text to analyze
            top_k: Number of similar patterns to retrieve
            
        Returns:
            SemanticDetectionResult with detection details
        """
        if not text or len(text.strip()) == 0:
            return SemanticDetectionResult(
                is_safe=True,
                risk_score=0.0,
                explanation="Empty input"
            )
        
        try:
            # Generate embedding for input text
            query_embedding = self.model.encode([text])[0]
            
            # Query ChromaDB for similar patterns
            results = self.collection.query(
                query_embeddings=[query_embedding.tolist()],
                n_results=top_k,
                include=["documents", "metadatas", "distances"]
            )
            
            # Process results
            similar_patterns = []
            max_similarity = 0.0
            detected_threats = []
            
            if results and results['distances'] and len(results['distances'][0]) > 0:
                for i, distance in enumerate(results['distances'][0]):
                    # Convert L2 distance to cosine similarity (approximate)
                    # For normalized embeddings: similarity ≈ 1 - (distance² / 2)
                    similarity = 1 - (distance ** 2 / 2)
                    similarity = max(0.0, min(1.0, similarity))  # Clamp to [0, 1]
                    
                    metadata = results['metadatas'][0][i]
                    document = results['documents'][0][i]
                    
                    similar_patterns.append({
                        "text": document,
                        "category": metadata.get("category", "unknown"),
                        "severity": metadata.get("severity", 50),
                        "similarity": round(similarity, 3)
                    })
                    
                    # Check if similarity exceeds threshold
                    if similarity >= self.similarity_threshold:
                        category = metadata.get("category", "unknown")
                        severity = metadata.get("severity", 50)
                        
                        # Skip safe patterns
                        if category != "safe":
                            max_similarity = max(max_similarity, similarity)
                            detected_threats.append({
                                "category": category,
                                "similarity": round(similarity, 3),
                                "severity": severity,
                                "matched_pattern": document[:100]
                            })
            
            # Calculate risk score
            if detected_threats:
                # Use highest similarity and severity
                risk_score = max_similarity * 100
                is_safe = False
                
                # Group threats by category
                threat_names = list(set(t["category"] for t in detected_threats))
                
                explanation = f"Detected {len(detected_threats)} semantically similar threat(s)"
            else:
                risk_score = 0.0
                is_safe = True
                threat_names = []
                explanation = "No semantic threats detected"
            
            return SemanticDetectionResult(
                is_safe=is_safe,
                risk_score=risk_score,
                threats=threat_names,
                explanation=explanation,
                similar_patterns=similar_patterns
            )
            
        except Exception as e:
            logger.error(f"Semantic detection error: {e}", exc_info=True)
            return SemanticDetectionResult(
                is_safe=True,
                risk_score=0.0,
                explanation=f"Detection error: {str(e)}"
            )
    
    def add_pattern(
        self,
        text: str,
        category: str,
        severity: int = 50
    ) -> bool:
        """
        Add a new attack pattern to the database.
        
        Args:
            text: Attack pattern text
            category: Threat category
            severity: Severity score (0-100)
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Generate embedding
            embedding = self.model.encode([text])[0]
            
            # Generate unique ID
            pattern_id = f"pattern_{self.collection.count()}"
            
            # Add to collection
            self.collection.add(
                ids=[pattern_id],
                embeddings=[embedding.tolist()],
                documents=[text],
                metadatas=[{
                    "category": category,
                    "severity": severity,
                    "text": text[:200]
                }]
            )
            
            logger.info(f"Added new pattern: {category} (severity: {severity})")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add pattern: {e}")
            return False
    
    def reset_database(self):
        """Reset the database and reinitialize with default patterns"""
        logger.warning("Resetting semantic detection database...")
        self.client.delete_collection("sentinel_threats")
        self.collection = self.client.get_or_create_collection(
            name="sentinel_threats",
            metadata={"description": "SENTINEL threat pattern embeddings"}
        )
        self._initialize_database()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get database statistics"""
        total_patterns = self.collection.count()
        
        # Get category distribution
        if total_patterns > 0:
            results = self.collection.get(include=["metadatas"])
            categories = {}
            for metadata in results['metadatas']:
                cat = metadata.get('category', 'unknown')
                categories[cat] = categories.get(cat, 0) + 1
        else:
            categories = {}
        
        return {
            "total_patterns": total_patterns,
            "categories": categories,
            "model": self.model_name,
            "similarity_threshold": self.similarity_threshold
        }


# Singleton instance for reuse
_detector_instance: Optional[SemanticDetector] = None


def get_semantic_detector(
    model_name: str = "all-MiniLM-L6-v2",
    similarity_threshold: float = 0.75
) -> SemanticDetector:
    """Get or create singleton semantic detector instance"""
    global _detector_instance
    
    if _detector_instance is None:
        _detector_instance = SemanticDetector(
            model_name=model_name,
            similarity_threshold=similarity_threshold
        )
    
    return _detector_instance
