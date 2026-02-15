/**
 * Security Event Tracker
 * 
 * Standalone library for tracking security events and session analytics.
 */

export type ThreatLevel = 1 | 2 | 3 | 4;

export interface SecurityEvent {
  id: string;
  sessionId: string;
  timestamp: string;
  type: 'clean' | 'threat_detected' | 'data_access' | 'containment';
  threatLevel: ThreatLevel;
  details: Record<string, any>;
  contained?: boolean;
}

export interface SessionSummary {
  sessionId: string;
  eventCount: number;
  threatCount: number;
  maxThreatLevel: ThreatLevel;
  startTime: string;
  endTime?: string;
  duration?: number;
}

export interface Analytics {
  totalSessions: number;
  totalEvents: number;
  threatEvents: number;
  quarantineCount: number;
  averageThreatLevel: number;
}

export class SecurityEventTracker {
  private sessions: Map<string, SecurityEvent[]>;
  private eventIndex: Map<string, SecurityEvent>;

  constructor() {
    this.sessions = new Map();
    this.eventIndex = new Map();
  }

  /**
   * Track a security event
   */
  track(event: SecurityEvent): void {
    // Store in index
    this.eventIndex.set(event.id, event);

    // Add to session
    if (!this.sessions.has(event.sessionId)) {
      this.sessions.set(event.sessionId, []);
    }
    this.sessions.get(event.sessionId)!.push(event);
  }

  /**
   * Get session events
   */
  getSessionEvents(sessionId: string): SecurityEvent[] {
    return this.sessions.get(sessionId) || [];
  }

  /**
   * Get session summary
   */
  getSessionSummary(sessionId: string): SessionSummary | null {
    const events = this.sessions.get(sessionId);
    if (!events || events.length === 0) return null;

    const threatEvents = events.filter(e => e.threatLevel > 1);
    const maxThreat = Math.max(...events.map(e => e.threatLevel)) as ThreatLevel;
    const firstEvent = events[0];
    const lastEvent = events[events.length - 1];

    return {
      sessionId,
      eventCount: events.length,
      threatCount: threatEvents.length,
      maxThreatLevel: maxThreat,
      startTime: firstEvent.timestamp,
      endTime: lastEvent.timestamp,
      duration: new Date(lastEvent.timestamp).getTime() - new Date(firstEvent.timestamp).getTime()
    };
  }

  /**
   * Get all sessions
   */
  getSessions(): string[] {
    return Array.from(this.sessions.keys());
  }

  /**
   * Get analytics
   */
  getAnalytics(): Analytics {
    let totalEvents = 0;
    let threatEvents = 0;
    let quarantineCount = 0;
    let totalThreatLevel = 0;

    for (const events of this.sessions.values()) {
      totalEvents += events.length;
      for (const event of events) {
        if (event.threatLevel > 1) {
          threatEvents++;
        }
        if (event.contained) {
          quarantineCount++;
        }
        totalThreatLevel += event.threatLevel;
      }
    }

    return {
      totalSessions: this.sessions.size,
      totalEvents,
      threatEvents,
      quarantineCount,
      averageThreatLevel: totalEvents > 0 ? totalThreatLevel / totalEvents : 0
    };
  }

  /**
   * Search events by type
   */
  searchByType(type: SecurityEvent['type']): SecurityEvent[] {
    const results: SecurityEvent[] = [];
    for (const event of this.eventIndex.values()) {
      if (event.type === type) {
        results.push(event);
      }
    }
    return results;
  }

  /**
   * Search events by threat level
   */
  searchByThreatLevel(level: ThreatLevel): SecurityEvent[] {
    const results: SecurityEvent[] = [];
    for (const event of this.eventIndex.values()) {
      if (event.threatLevel >= level) {
        results.push(event);
      }
    }
    return results;
  }

  /**
   * Get recent events
   */
  getRecentEvents(limit: number = 100): SecurityEvent[] {
    return Array.from(this.eventIndex.values())
      .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
      .slice(0, limit);
  }

  /**
   * Clear old events
   */
  clearOlderThan(timestamp: string): number {
    const cutoff = new Date(timestamp).getTime();
    let cleared = 0;

    for (const [eventId, event] of this.eventIndex) {
      if (new Date(event.timestamp).getTime() < cutoff) {
        this.eventIndex.delete(eventId);
        cleared++;
      }
    }

    return cleared;
  }
}

export default SecurityEventTracker;
