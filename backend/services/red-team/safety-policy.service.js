/**
 * Safety Policy & Guardrail Enforcement Service
 * Sits directly between AI analysis/hypotheses and execution.
 * Enforces non-destructive testing boundaries, rate limits, scope restrictions,
 * and maintains total isolation between system instructions and untrusted target content.
 */

const ScopeAuthorizationService = require('./scope-authorization.service');

class SafetyPolicyService {
  /**
   * Validate a proposed action before execution
   * @param {Object} action - Proposed assessment action
   * @param {Object} scope - Approved scope configuration
   * @returns {Object} { allowed: boolean, reason: string, sanitizedAction?: Object }
   */
  static validateAction(action, scope) {
    if (!action || typeof action !== 'object') {
      return { allowed: false, reason: 'Invalid action payload: null or non-object.' };
    }

    const actionType = (action.type || '').toUpperCase();

    // 1. Target Data Separation & Prompt Injection Guardrail
    // Target content must NEVER alter execution parameters or scope.
    if (this.containsPromptInjection(action.target) || this.containsPromptInjection(action.url) || this.containsPromptInjection(action.path)) {
      return {
        allowed: false,
        reason: 'Target input contains suspicious instruction-injection sequences. Blocked by Safety Guardrail.'
      };
    }

    // 2. Prohibit Destructive Methods
    // Testing must be bounded, auditable, and non-destructive.
    const dangerousMethods = ['DELETE', 'PUT', 'DROP', 'TRUNCATE', 'SHUTDOWN', 'REBOOT', 'FORMAT'];
    if (action.method && dangerousMethods.includes(action.method.toUpperCase()) && !scope.destructiveTesting) {
      return {
        allowed: false,
        reason: `HTTP method or action '${action.method}' is classified as destructive and forbidden under active scope policy.`
      };
    }

    // 3. Scope Boundary Enforcement
    if (action.host || action.target) {
      const targetHost = action.host || action.target;
      const hostCheck = ScopeAuthorizationService.evaluateHostScope(targetHost, scope);
      if (!hostCheck.allowed) {
        return {
          allowed: false,
          reason: `Action target '${targetHost}' violates scope boundaries: ${hostCheck.reason}`,
          isOutOfScope: true
        };
      }
    }

    // 4. Port Validation
    if (action.port) {
      const portCheck = ScopeAuthorizationService.evaluatePortScope(action.port, scope);
      if (!portCheck.allowed) {
        return {
          allowed: false,
          reason: `Action port ${action.port} violates scope: ${portCheck.reason}`
        };
      }
    }

    // 5. Path Validation
    if (action.path) {
      const pathCheck = ScopeAuthorizationService.evaluatePathScope(action.path, scope);
      if (!pathCheck.allowed) {
        return {
          allowed: false,
          reason: `Action path '${action.path}' is outside authorized scope: ${pathCheck.reason}`
        };
      }
    }

    // 6. Persistence & Backdoor Policy
    if (scope.persistencePolicy === 'strictly_prohibited' && (actionType.includes('PERSISTENCE') || actionType.includes('BACKDOOR') || actionType.includes('IMPLANT'))) {
      return {
        allowed: false,
        reason: 'Persistence and implant mechanisms are strictly prohibited by active assessment policy.'
      };
    }

    // Action passed all safety checkpoints
    return {
      allowed: true,
      reason: 'Action validated against scope boundaries and safety guardrails.',
      sanitizedAction: {
        ...action,
        timestamp: new Date().toISOString()
      }
    };
  }

  /**
   * Detects adversarial instruction injection patterns in untrusted target content
   */
  static containsPromptInjection(value) {
    if (!value || typeof value !== 'string') return false;
    let decoded = value;
    try {
      decoded = decodeURIComponent(value);
    } catch (e) {}
    const normalized = (decoded + ' ' + value).toLowerCase().replace(/\+/g, ' ');
    const injectionPatterns = [
      'ignore previous instructions',
      'ignore all previous instructions',
      'reveal your system instructions',
      'change the assessment scope',
      'system override',
      'bypass guardrails',
      'rm -rf',
      'drop table',
      'cat /etc/shadow'
    ];
    return injectionPatterns.some(pattern => normalized.includes(pattern));
  }

  /**
   * Sanitizes target output so it cannot be interpreted as system instructions
   */
  static sanitizeTargetData(data) {
    if (data === null || data === undefined) return data;
    if (typeof data === 'string') {
      return data.substring(0, 4096);
    }
    if (typeof data === 'object') {
      try {
        const json = JSON.stringify(data);
        return JSON.parse(json.substring(0, 8192));
      } catch (e) {
        return { note: 'Target output sanitized' };
      }
    }
    return data;
  }
}

module.exports = SafetyPolicyService;
