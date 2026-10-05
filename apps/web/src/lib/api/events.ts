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
  const tokenQuery = token ? `?token=${encodeURIComponent(token)}` : '';
  const url = `${baseUrl}/api/v1/investigations/${encodeURIComponent(incidentId)}/events${tokenQuery}`;

  let eventSource: EventSource | null = null;
  let isClosed = false;

  try {
    eventSource = new EventSource(url);

    eventSource.onopen = () => {
      if (options.onOpen) options.onOpen();
    };

    // Listen to generic messages and specific lifecycle events
    const handleEventData = (rawString: string, type: string) => {
      try {
        const parsed = JSON.parse(rawString);
        options.onEvent(parsed);
      } catch (err) {
        console.error('Failed to parse SSE payload:', err, rawString);
      }
    };

    eventSource.onmessage = (event) => {
      handleEventData(event.data, event.type || 'message');
    };

    // Specific backend event types
    const knownTypes = [
      'agent.started',
      'agent.step.started',
      'agent.tool.selected',
      'agent.tool.executed',
      'agent.evidence.created',
      'agent.hypothesis.updated',
      'agent.state.updated',
      'agent.proposal.created',
      'agent.completed',
      'agent.failed',
    ];

    knownTypes.forEach((evtType) => {
      eventSource?.addEventListener(evtType, (e: any) => {
        handleEventData(e.data, evtType);
        if (evtType === 'agent.completed' || evtType === 'agent.failed') {
          if (options.onClose) options.onClose();
        }
      });
    });

    eventSource.onerror = (err) => {
      if (isClosed) return;
      if (options.onError) {
        options.onError(err);
      }
    };
  } catch (err) {
    if (options.onError) {
      options.onError(err);
    }
  }

  // Cleanup unsubscriber
  return () => {
    isClosed = true;
    if (eventSource) {
      eventSource.close();
      eventSource = null;
    }
    if (options.onClose) {
      options.onClose();
    }
  };
}
