"""
LLM Service for SENTINEL Brain

Integrates with Hugging Face Router API using OpenAI SDK.
"""

import os
import logging
from typing import Optional

logger = logging.getLogger("LLMService")


class LLMService:
    """Service for interacting with Hugging Face LLM models via Router API."""

    def __init__(self):
        # Support multiple token names
        self.api_key = (
            os.environ.get("HUGGINGFACE_API_KEY") 
            or os.environ.get("HF_TOKEN") 
            or os.environ.get("HR_TOKEN", "")
        )
        self.model = os.environ.get("LLM_MODEL", "openai/gpt-oss-120b:fireworks-ai")
        self.timeout = float(os.environ.get("LLM_TIMEOUT", "60.0"))
        self.max_tokens = int(os.environ.get("LLM_MAX_TOKENS", "150"))
        
        # Log configuration
        if self.api_key:
            logger.info(f"LLM Service initialized with model: {self.model}")
            logger.info(f"API Key configured: {self.api_key[:10]}...")
            logger.info("Using Hugging Face Router API with OpenAI SDK")
        else:
            logger.error("LLM Service initialized WITHOUT API key!")
            logger.error("Set HUGGINGFACE_API_KEY or HF_TOKEN in .env file")

    async def generate_response(self, prompt: str) -> Optional[str]:
        """
        Generate a response from the LLM using OpenAI SDK with HF Router.

        Args:
            prompt: The user's input text

        Returns:
            Generated response text or error message
        """
        # Fail if no API key
        if not self.api_key:
            logger.error("Cannot generate response: No API key configured")
            return "ERROR: No API key configured. Add HUGGINGFACE_API_KEY or HF_TOKEN to .env file."
        
        try:
            # Import OpenAI SDK
            try:
                from openai import OpenAI
            except ImportError:
                logger.error("OpenAI SDK not installed")
                return "ERROR: OpenAI SDK not installed. Run: pip install openai"

            # Create OpenAI client with HF Router
            client = OpenAI(
                base_url="https://router.huggingface.co/v1",
                api_key=self.api_key,
                timeout=self.timeout,
            )

            logger.info(f"Calling Hugging Face Router API with model: {self.model}")
            
            # Make chat completion request (exactly like your working code)
            completion = client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "user", "content": prompt}
                ],
                max_tokens=self.max_tokens,
                temperature=0.7,
            )

            # Debug logging
            logger.info(f"Completion object: {completion}")
            logger.info(f"Completion type: {type(completion)}")
            logger.info(f"Has choices: {hasattr(completion, 'choices')}")
            
            if hasattr(completion, 'choices'):
                logger.info(f"Number of choices: {len(completion.choices)}")
                if completion.choices and len(completion.choices) > 0:
                    logger.info(f"First choice: {completion.choices[0]}")
                    logger.info(f"Message: {completion.choices[0].message}")
                    logger.info(f"Message content: {completion.choices[0].message.content}")

            # Extract response (exactly like your working code)
            if completion.choices and len(completion.choices) > 0:
                message = completion.choices[0].message
                if message and message.content:
                    response_text = message.content
                    logger.info(f"LLM response generated successfully: {response_text[:200]}")
                    return response_text
                else:
                    logger.warning(f"Empty message content. Message object: {message}")
                    # Try to get any text from the response
                    if hasattr(message, 'text'):
                        logger.info(f"Found 'text' attribute: {message.text}")
                        return message.text
                    return "Empty response from model. The model may be loading. Try again in 30 seconds."
            else:
                logger.warning(f"No choices in response. Full completion: {completion}")
                return "No response generated. Try again."
                
        except ImportError as e:
            logger.error(f"Import error: {e}")
            return "ERROR: OpenAI SDK not installed. Run: pip install openai"
            
        except Exception as e:
            error_msg = str(e)
            logger.error(f"LLM generation failed: {error_msg}", exc_info=True)
            
            # Handle specific errors
            if "timeout" in error_msg.lower():
                return "Request timed out. Try again."
            elif "not found" in error_msg.lower() or "404" in error_msg:
                return f"ERROR: Model '{self.model}' not found."
            elif "unauthorized" in error_msg.lower() or "401" in error_msg:
                return "ERROR: Invalid API key."
            elif "not supported" in error_msg.lower():
                return f"ERROR: Model '{self.model}' not supported. Check model name in .env"
            else:
                return f"ERROR: {error_msg}"

    def is_configured(self) -> bool:
        """Check if LLM service is properly configured."""
        return bool(self.api_key)


# Singleton instance
_llm_service = None


def get_llm_service() -> LLMService:
    """Get or create the LLM service instance."""
    global _llm_service
    if _llm_service is None:
        _llm_service = LLMService()
    return _llm_service
