#!/bin/bash

echo "======================================================================"
echo "🤖 SENTINEL Brain - LLM Setup"
echo "======================================================================"
echo ""

# Check if .env exists
if [ -f ".env" ]; then
    echo "✅ .env file found"
else
    echo "Creating .env from .env.example..."
    cp .env.example .env
    echo "✅ .env file created"
fi

echo ""
echo "======================================================================"
echo "Configuration Steps:"
echo "======================================================================"
echo ""
echo "1. Get your Hugging Face API key:"
echo "   👉 https://huggingface.co/settings/tokens"
echo ""
echo "2. Open .env file and add:"
echo "   HUGGINGFACE_API_KEY=hf_your_token_here"
echo ""
echo "3. Choose a model (optional, default is gpt2):"
echo "   LLM_MODEL=gpt2"
echo ""
echo "4. Save the file"
echo ""
echo "======================================================================"
echo ""

read -p "Open .env file now? (y/n): " OPEN_ENV
if [ "$OPEN_ENV" = "y" ] || [ "$OPEN_ENV" = "Y" ]; then
    if command -v nano &> /dev/null; then
        nano .env
    elif command -v vim &> /dev/null; then
        vim .env
    elif command -v vi &> /dev/null; then
        vi .env
    else
        echo "Please open .env manually with your preferred editor"
    fi
fi

echo ""
echo "======================================================================"
echo "Next Steps:"
echo "======================================================================"
echo ""
echo "1. Configure your API key in .env"
echo "2. Run: ./start_backend.sh"
echo "3. Run: cd front && npm run dev"
echo "4. Open: http://localhost:3000"
echo ""
echo "======================================================================"
