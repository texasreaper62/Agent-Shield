'use strict';

/**
 * Agent Shield — Framework Integration Wrappers
 *
 * Plug-and-play integrations for next-generation AI agent frameworks:
 * - CrewAI (task decorators & callbacks)
 * - Google Agent Development Kit (plugin system)
 * - Microsoft Agent Framework (middleware pipeline)
 *
 * These close gaps identified in the Microsoft Agent Governance Toolkit
 * parity audit.
 *
 * @module integrations-frameworks
 */

const { AgentShield } = require('./index');
const { ShieldBlockError } = require('./integrations');

// =========================================================================
// CrewAI Integration
// =========================================================================

/**
 * Creates Agent Shield callbacks for CrewAI task lifecycle.
 *
 * CrewAI uses task decorators and callbacks. This wrapper provides
 * beforeTask / afterTask hooks that scan task descriptions, expected
 * outputs, and task results for prompt injection and other threats.
 *
 * Usage:
 *   const { shieldCrewAI } = require('agentshield-sdk/src/integrations-frameworks');
 *   const { beforeTask, afterTask } = shieldCrewAI({ blockOnThreat: true });
 *
 *   // In your CrewAI task lifecycle:
 *   beforeTask(task, agent);       // throws ShieldBlockError if threat found
 *   const output = await task.run();
 *   afterTask(task, output);       // throws ShieldBlockError if threat found
 *
 * @param {object} [options]
 * @param {string} [options.sensitivity='high'] - Detection sensitivity level.
 * @param {boolean} [options.blockOnThreat=true] - Whether to throw on threat detection.
 * @param {string} [options.blockThreshold='high'] - Minimum severity that triggers a block.
 * @param {function} [options.onThreat] - Callback when a threat is detected.
 * @returns {{ beforeTask: function, afterTask: function, shield: AgentShield }}
 */
function shieldCrewAI(options = {}) {
  const shield = new AgentShield({
    sensitivity: options.sensitivity || 'high',
    blockOnThreat: options.blockOnThreat !== false,
    blockThreshold: options.blockThreshold || 'high'
  });
  const onThreat = options.onThreat || null;

  /**
   * Scans a CrewAI task before execution.
   * Inspects task.description and task.expected_output for injection.
   *
   * @param {object} task - CrewAI task object.
   * @param {object} [agent] - CrewAI agent assigned to the task.
   * @throws {ShieldBlockError} If a threat is detected and blocking is enabled.
   */
  function beforeTask(task, agent) {
    if (!task) return;

    const fields = [];
    if (task.description) fields.push(String(task.description));
    if (task.expected_output) fields.push(String(task.expected_output));

    for (const text of fields) {
      const result = shield.scanInput(text);
      if (result.threats && result.threats.length > 0) {
        if (onThreat) {
          try {
            onThreat({
              phase: 'before_task',
              threats: result.threats,
              task: task.description || '',
              agent: agent && agent.role ? agent.role : undefined
            });
          } catch (e) {
            console.error('[Agent Shield] onThreat callback error:', e.message);
          }
        }
        if (result.blocked) {
          throw new ShieldBlockError('CrewAI task blocked by Agent Shield', result.threats);
        }
      }
    }
  }

  /**
   * Scans a CrewAI task output after execution.
   *
   * @param {object} task - CrewAI task object.
   * @param {*} output - Task execution output.
   * @throws {ShieldBlockError} If a threat is detected and blocking is enabled.
   */
  function afterTask(task, output) {
    if (output == null) return;

    const text = typeof output === 'string' ? output : JSON.stringify(output);
    const result = shield.scanOutput(text);

    if (result.threats && result.threats.length > 0) {
      if (onThreat) {
        try {
          onThreat({
            phase: 'after_task',
            threats: result.threats,
            task: task && task.description ? task.description : ''
          });
        } catch (e) {
          console.error('[Agent Shield] onThreat callback error:', e.message);
        }
      }
      if (result.blocked) {
        throw new ShieldBlockError('CrewAI task output blocked by Agent Shield', result.threats);
      }
    }
  }

  return { beforeTask, afterTask, shield };
}

// =========================================================================
// Google Agent Development Kit (ADK) Integration
// =========================================================================

/**
 * Creates Agent Shield hooks for the Google Agent Development Kit plugin system.
 *
 * Google ADK uses a plugin architecture with lifecycle hooks. This wrapper
 * provides beforeToolCall, afterToolCall, and beforeGenerate functions that
 * scan tool arguments, tool results, and generation prompts for threats.
 *
 * Usage:
 *   const { shieldGoogleADK } = require('agentshield-sdk/src/integrations-frameworks');
 *   const hooks = shieldGoogleADK({ blockOnThreat: true });
 *
 *   // Register as ADK plugin callbacks:
 *   hooks.beforeToolCall('web_search', { query: userInput });
 *   const result = await tool.execute(args);
 *   hooks.afterToolCall('web_search', result);
 *   hooks.beforeGenerate(prompt);
 *
 * @param {object} [options]
 * @param {string} [options.sensitivity='high'] - Detection sensitivity level.
 * @param {boolean} [options.blockOnThreat=true] - Whether to throw on threat detection.
 * @param {string} [options.blockThreshold='high'] - Minimum severity that triggers a block.
 * @param {function} [options.onThreat] - Callback when a threat is detected.
 * @returns {{ beforeToolCall: function, afterToolCall: function, beforeGenerate: function, shield: AgentShield }}
 */
function shieldGoogleADK(options = {}) {
  const shield = new AgentShield({
    sensitivity: options.sensitivity || 'high',
    blockOnThreat: options.blockOnThreat !== false,
    blockThreshold: options.blockThreshold || 'high'
  });
  const onThreat = options.onThreat || null;

  /**
   * Scans tool arguments before a tool call.
   *
   * @param {string} toolName - Name of the tool being called.
   * @param {*} args - Tool arguments (object, string, or any serializable value).
   * @throws {ShieldBlockError} If a threat is detected and blocking is enabled.
   */
  function beforeToolCall(toolName, args) {
    if (args == null) return;

    const text = typeof args === 'string' ? args : JSON.stringify(args);
    const result = shield.scanInput(text);

    if (result.threats && result.threats.length > 0) {
      if (onThreat) {
        try {
          onThreat({
            phase: 'before_tool_call',
            toolName: toolName || 'unknown',
            threats: result.threats
          });
        } catch (e) {
          console.error('[Agent Shield] onThreat callback error:', e.message);
        }
      }
      if (result.blocked) {
        throw new ShieldBlockError(
          `Google ADK tool "${toolName || 'unknown'}" call blocked by Agent Shield`,
          result.threats
        );
      }
    }
  }

  /**
   * Scans tool results after a tool call.
   *
   * @param {string} toolName - Name of the tool that was called.
   * @param {*} result - Tool execution result.
   * @throws {ShieldBlockError} If a threat is detected and blocking is enabled.
   */
  function afterToolCall(toolName, toolResult) {
    if (toolResult == null) return;

    const text = typeof toolResult === 'string' ? toolResult : JSON.stringify(toolResult);
    const result = shield.scanOutput(text);

    if (result.threats && result.threats.length > 0) {
      if (onThreat) {
        try {
          onThreat({
            phase: 'after_tool_call',
            toolName: toolName || 'unknown',
            threats: result.threats
          });
        } catch (e) {
          console.error('[Agent Shield] onThreat callback error:', e.message);
        }
      }
      if (result.blocked) {
        throw new ShieldBlockError(
          `Google ADK tool "${toolName || 'unknown'}" result blocked by Agent Shield`,
          result.threats
        );
      }
    }
  }

  /**
   * Scans a prompt before generation.
   *
   * @param {string|*} prompt - The prompt to scan.
   * @throws {ShieldBlockError} If a threat is detected and blocking is enabled.
   */
  function beforeGenerate(prompt) {
    if (prompt == null) return;

    const text = typeof prompt === 'string' ? prompt : JSON.stringify(prompt);
    const result = shield.scanInput(text);

    if (result.threats && result.threats.length > 0) {
      if (onThreat) {
        try {
          onThreat({
            phase: 'before_generate',
            threats: result.threats
          });
        } catch (e) {
          console.error('[Agent Shield] onThreat callback error:', e.message);
        }
      }
      if (result.blocked) {
        throw new ShieldBlockError('Google ADK generation blocked by Agent Shield', result.threats);
      }
    }
  }

  return { beforeToolCall, afterToolCall, beforeGenerate, shield };
}

// =========================================================================
// Microsoft Agent Framework Integration
// =========================================================================

/**
 * Creates Agent Shield middleware for the Microsoft Agent Framework pipeline.
 *
 * The MS Agent Framework uses a middleware pattern where each middleware
 * receives a context and a next() function. This wrapper scans context.input
 * before calling next(), then scans context.output after next() returns.
 *
 * Usage:
 *   const { shieldMSAgentFramework } = require('agentshield-sdk/src/integrations-frameworks');
 *   const { agentMiddleware } = shieldMSAgentFramework({ blockOnThreat: true });
 *
 *   // Register in the MS Agent Framework pipeline:
 *   agent.use(agentMiddleware);
 *
 * @param {object} [options]
 * @param {string} [options.sensitivity='high'] - Detection sensitivity level.
 * @param {boolean} [options.blockOnThreat=true] - Whether to throw on threat detection.
 * @param {string} [options.blockThreshold='high'] - Minimum severity that triggers a block.
 * @param {function} [options.onThreat] - Callback when a threat is detected.
 * @returns {{ agentMiddleware: function, shield: AgentShield }}
 */
function shieldMSAgentFramework(options = {}) {
  const shield = new AgentShield({
    sensitivity: options.sensitivity || 'high',
    blockOnThreat: options.blockOnThreat !== false,
    blockThreshold: options.blockThreshold || 'high'
  });
  const onThreat = options.onThreat || null;

  /**
   * Middleware function for the MS Agent Framework pipeline.
   * Scans context.input before next() and context.output after next().
   *
   * @param {object} context - Pipeline context with input/output properties.
   * @param {function} next - Next middleware in the pipeline.
   * @throws {ShieldBlockError} If a threat is detected and blocking is enabled.
   */
  async function agentMiddleware(context, next) {
    // Scan input before passing to next middleware
    if (context && context.input != null) {
      const inputText = typeof context.input === 'string'
        ? context.input
        : JSON.stringify(context.input);

      const inputResult = shield.scanInput(inputText);

      if (inputResult.threats && inputResult.threats.length > 0) {
        if (onThreat) {
          try {
            onThreat({
              phase: 'input',
              threats: inputResult.threats,
              text: inputText
            });
          } catch (e) {
            console.error('[Agent Shield] onThreat callback error:', e.message);
          }
        }
        if (inputResult.blocked) {
          throw new ShieldBlockError(
            'MS Agent Framework input blocked by Agent Shield',
            inputResult.threats
          );
        }
      }
    }

    // Call next middleware in the pipeline
    await next();

    // Scan output after pipeline execution
    if (context && context.output != null) {
      const outputText = typeof context.output === 'string'
        ? context.output
        : JSON.stringify(context.output);

      const outputResult = shield.scanOutput(outputText);

      if (outputResult.threats && outputResult.threats.length > 0) {
        if (onThreat) {
          try {
            onThreat({
              phase: 'output',
              threats: outputResult.threats,
              text: outputText
            });
          } catch (e) {
            console.error('[Agent Shield] onThreat callback error:', e.message);
          }
        }
        if (outputResult.blocked) {
          throw new ShieldBlockError(
            'MS Agent Framework output blocked by Agent Shield',
            outputResult.threats
          );
        }
      }
    }
  }

  return { agentMiddleware, shield };
}

module.exports = {
  shieldCrewAI,
  shieldGoogleADK,
  shieldMSAgentFramework
};
