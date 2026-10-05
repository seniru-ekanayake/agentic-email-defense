import { getBaseUrl } from './client';
import { AgentLifecycleEvent } from './types';

export interface SSEConnectionOptions {
  onEvent: (event: AgentLifecycleEvent) => void;
  onError?: (error: any) => void;
  onOpen?: () => void;
  onClose?: () => void;
}

export function subscribeInvestigationEvents(
  incidentId: string,
  options: SSEConnectionOptions
): () => void {
  const baseUrl = getBaseUrl();
  const token = typeof window !== 'undefined'
    ? (localStorage.getItem('fishingmails_auth_token') || sessionStorage.getItem('fishingmails_auth_token'))
    : (process.env.NEXT_PUBLIC_AUTH_TOKEN || null);
  const url = `${baseUrl}/api/v1/investigations/${encodeURIComponent(incidentId)}/events`;

  let isClosed = false;
  const abortController = new AbortController();

  const handleEventData = (rawString: string, type: string) => {
    try {
      const parsed = JSON.parse(rawString);
      options.onEvent(parsed);
    } catch (err) {
      console.error('Failed to parse SSE payload:', err, rawString);
    }
  };

  const startStream = async () => {
    try {
      const headers: Record<string, string> = {
        'Accept': 'text/event-stream',
      };
      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }

      const res = await fetch(url, {
        headers,
        signal: abortController.signal,
      });

      if (!res.ok) {
        throw new Error(`SSE stream connection failed with HTTP status ${res.status}`);
      }

      if (options.onOpen) {
        options.onOpen();
      }

      if (!res.body) {
        throw new Error('Response body not available for streaming');
      }

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      while (!isClosed) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\\n');
        buffer = lines.pop() || '';

        let currentEvent = 'message';
        let currentData = '';

        for (const line of lines) {
          if (line.startsWith('event:')) {
            currentEvent = line.slice(6).trim();
          } else if (line.startsWith('data:')) {
            currentData = line.slice(5).trim();
          } else if (line === '') {
            if (currentData) {
              handleEventData(currentData, currentEvent);
              if (currentEvent === 'agent.completed' || currentEvent === 'agent.failed') {
                if (options.onClose) options.onClose();
              }
              currentEvent = 'message';
              currentData = '';
            }
          }
        }
      }
    } catch (err: any) {
      if (isClosed || err?.name === 'AbortError') return;
      if (options.onError) {
        options.onError(err);
      }
    } finally {
      if (!isClosed && options.onClose) {
        options.onClose();
      }
    }
  };

  startStream();

  // Cleanup unsubscriber
  return () => {
    isClosed = true;
    abortController.abort();
    if (options.onClose) {
      options.onClose();
    }
  };
}
