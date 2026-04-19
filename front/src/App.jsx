import { useState, useRef, useEffect } from 'react';
import './App.css';

function App() {
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const messagesEndRef = useRef(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const analyzeText = async (text) => {
    setLoading(true);
    try {
      const response = await fetch('/v1/analyze', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          text: text,
          profile: 'standard',
        }),
      });

      const data = await response.json();
      return data;
    } catch (error) {
      console.error('Error analyzing text:', error);
      return {
        verdict: 'ERROR',
        error: error.message,
      };
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!input.trim() || loading) return;

    const userMessage = input.trim();
    setInput('');

    // Add user message
    setMessages((prev) => [
      ...prev,
      {
        type: 'user',
        content: userMessage,
        timestamp: new Date().toISOString(),
      },
    ]);

    // Analyze the message
    const analysis = await analyzeText(userMessage);

    // Add system response
    setMessages((prev) => [
      ...prev,
      {
        type: 'system',
        content: userMessage,
        analysis: analysis,
        timestamp: new Date().toISOString(),
      },
    ]);
  };

  const formatTimestamp = (timestamp) => {
    const date = new Date(timestamp);
    return date.toLocaleTimeString('en-US', {
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  return (
    <div className="app">
      <header className="header">
        <h1>SENTINEL Brain</h1>
        <p>AI Security Analysis Platform</p>
        {messages.length > 0 && messages.some(m => m.analysis?.llm_response?.includes('mock')) && (
          <div className="mock-indicator">
            Using Mock AI - Configure HUGGINGFACE_API_KEY for real responses
          </div>
        )}
      </header>

      <div className="chat-container">
        <div className="messages">
          {messages.length === 0 && (
            <div className="welcome">
              <h2>Welcome to SENTINEL Brain</h2>
              <p>Send a message to analyze it for security threats</p>
            </div>
          )}

          {messages.map((message, index) => (
            <div key={index} className={`message ${message.type}`}>
              {message.type === 'user' ? (
                <div className="message-content">
                  <div className="message-header">
                    <span className="message-label">User</span>
                    <span className="message-time">
                      {formatTimestamp(message.timestamp)}
                    </span>
                  </div>
                  <div className="message-text">{message.content}</div>
                </div>
              ) : (
                <div className="message-content">
                  <div className="message-header">
                    <span className="message-label">Analysis Result</span>
                    <span className="message-time">
                      {formatTimestamp(message.timestamp)}
                    </span>
                  </div>

                  {message.analysis.verdict === 'ALLOW' && (
                    <div className="verdict-allowed">
                      <div className="verdict-badge allowed">ALLOWED</div>
                      <div className="verdict-details">
                        <p className="verdict-message">
                          Message passed security analysis
                        </p>
                        <div className="risk-info">
                          <span>Risk Score: {message.analysis.risk_score.toFixed(1)}</span>
                          <span>Latency: {message.analysis.latency_ms.toFixed(0)}ms</span>
                        </div>
                      </div>
                      <details className="json-details">
                        <summary>View Full Analysis</summary>
                        <pre className="json-content">
                          {JSON.stringify(message.analysis, null, 2)}
                        </pre>
                      </details>
                      {message.analysis.llm_response && (
                        <div className="llm-response">
                          <div className="response-label">LLM Response</div>
                          <div className="response-content">
                            {message.analysis.llm_response}
                          </div>
                        </div>
                      )}
                      {!message.analysis.llm_response && (
                        <div className="llm-response llm-loading">
                          <div className="response-label">LLM Response</div>
                          <div className="response-content">
                            Generating response...
                          </div>
                        </div>
                      )}
                    </div>
                  )}

                  {message.analysis.verdict === 'BLOCK' && (
                    <div className="verdict-blocked">
                      <div className="verdict-badge blocked">BLOCKED</div>
                      <div className="verdict-details">
                        <p className="verdict-message">
                          Message blocked due to security threats
                        </p>
                        <div className="risk-info">
                          <span>Risk Score: {message.analysis.risk_score.toFixed(1)}</span>
                          <span>Threats: {message.analysis.threats.length}</span>
                        </div>
                      </div>
                      {message.analysis.threats.length > 0 && (
                        <div className="threats-list">
                          <div className="threats-label">Detected Threats:</div>
                          {message.analysis.threats.map((threat, idx) => (
                            <div key={idx} className="threat-item">
                              <span className="threat-name">{threat.name}</span>
                              <span className="threat-engine">{threat.engine}</span>
                              <span className="threat-confidence">
                                {(threat.confidence * 100).toFixed(0)}%
                              </span>
                            </div>
                          ))}
                        </div>
                      )}
                      <details className="json-details">
                        <summary>View Full Analysis</summary>
                        <pre className="json-content">
                          {JSON.stringify(message.analysis, null, 2)}
                        </pre>
                      </details>
                    </div>
                  )}

                  {message.analysis.verdict === 'WARN' && (
                    <div className="verdict-warned">
                      <div className="verdict-badge warned">WARNING</div>
                      <div className="verdict-details">
                        <p className="verdict-message">
                          Message contains potential security concerns
                        </p>
                        <div className="risk-info">
                          <span>Risk Score: {message.analysis.risk_score.toFixed(1)}</span>
                          <span>Threats: {message.analysis.threats.length}</span>
                        </div>
                      </div>
                      {message.analysis.threats.length > 0 && (
                        <div className="threats-list">
                          <div className="threats-label">Detected Threats:</div>
                          {message.analysis.threats.map((threat, idx) => (
                            <div key={idx} className="threat-item">
                              <span className="threat-name">{threat.name}</span>
                              <span className="threat-engine">{threat.engine}</span>
                              <span className="threat-confidence">
                                {(threat.confidence * 100).toFixed(0)}%
                              </span>
                            </div>
                          ))}
                        </div>
                      )}
                      <details className="json-details">
                        <summary>View Full Analysis</summary>
                        <pre className="json-content">
                          {JSON.stringify(message.analysis, null, 2)}
                        </pre>
                      </details>
                      {message.analysis.llm_response && (
                        <div className="llm-response llm-warning">
                          <div className="response-label">LLM Response (Proceed with Caution)</div>
                          <div className="response-content">
                            {message.analysis.llm_response}
                          </div>
                        </div>
                      )}
                    </div>
                  )}

                  {message.analysis.verdict === 'ERROR' && (
                    <div className="verdict-error">
                      <div className="verdict-badge error">ERROR</div>
                      <div className="verdict-details">
                        <p className="verdict-message">
                          Analysis failed: {message.analysis.error}
                        </p>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          ))}

          {loading && (
            <div className="message system">
              <div className="message-content">
                <div className="loading-indicator">
                  <span>Analyzing</span>
                  <span className="dots">...</span>
                </div>
              </div>
            </div>
          )}

          <div ref={messagesEndRef} />
        </div>

        <form className="input-form" onSubmit={handleSubmit}>
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Type a message to analyze..."
            disabled={loading}
            className="input-field"
          />
          <button type="submit" disabled={loading || !input.trim()} className="send-button">
            Send
          </button>
        </form>
      </div>
    </div>
  );
}

export default App;
