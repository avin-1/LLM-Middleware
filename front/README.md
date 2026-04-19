# SENTINEL Brain Frontend

A simple and elegant chat interface for the SENTINEL Brain API security analysis platform.

## Features

- Clean, professional chat interface
- Real-time security analysis of messages
- Three verdict types:
  - **ALLOWED**: Message passed security checks (shows full JSON and LLM response)
  - **WARNING**: Potential security concerns detected (shows threats and LLM response with caution)
  - **BLOCKED**: Security threats detected (shows full threat details and JSON)
- Expandable JSON analysis details
- Risk score and latency metrics
- Threat detection breakdown

## Setup

1. Install dependencies:
```bash
npm install
```

2. Start the development server:
```bash
npm run dev
```

3. Make sure the backend API is running on `http://localhost:8000`

## Backend Configuration

The frontend expects the SENTINEL Brain API to be running at:
- Default: `http://localhost:8000`
- Endpoint: `/v1/analyze`

To change the API URL, modify the `analyzeText` function in `src/App.jsx`.

## Build for Production

```bash
npm run build
```

The built files will be in the `dist` directory.

## Design Philosophy

- Simple and professional
- No gradients or decorative elements
- Clean typography and spacing
- Clear visual hierarchy
- Accessible color contrasts
- Responsive layout
