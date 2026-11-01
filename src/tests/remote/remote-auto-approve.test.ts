import { describe, expect, it, vi } from 'vitest';

vi.mock('../../main/utils/logger', () => ({
  log: vi.fn(),
  logError: vi.fn(),
  logWarn: vi.fn(),
}));

vi.mock('electron', () => ({
  app: { getPath: () => '/tmp', getVersion: () => '0.0.0' },
  BrowserWindow: class {},
}));

vi.mock('../../main/remote/remote-config-store', () => ({
  remoteConfigStore: { getAll: vi.fn(), get: vi.fn(), set: vi.fn() },
}));

const { isRemoteAutoApprovableTool } = await import('../../main/remote/remote-manager');

describe('isRemoteAutoApprovableTool', () => {
  it('allows read-only tools', () => {
    for (const tool of ['Read', 'Glob', 'Grep', 'LS', 'mcp__Chrome__take_screenshot']) {
      expect(isRemoteAutoApprovableTool(tool), tool).toBe(true);
    }
  });

  it('never auto-approves tools that can send data out or act in the browser', () => {
    for (const tool of [
      'WebFetch',
      'WebSearch',
      'Bash',
      'Write',
      'Edit',
      'Task',
      'mcp__Chrome__evaluate_script',
      'mcp__Chrome__navigate_page',
      'mcp__Chrome__new_page',
      'mcp__Chrome__click',
      'mcp__Chrome__fill',
      'mcp__Chrome__press_key',
    ]) {
      expect(isRemoteAutoApprovableTool(tool), tool).toBe(false);
    }
  });
});
