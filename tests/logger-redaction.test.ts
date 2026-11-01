import { describe, expect, it } from 'vitest';
import {
  isSensitiveLogKey,
  redactSecretsInText,
  serializeLogArg,
} from '../src/main/utils/logger';

describe('isSensitiveLogKey', () => {
  it('flags credential fields', () => {
    for (const key of [
      'apiKey',
      'api_key',
      'ANTHROPIC_API_KEY',
      'encryptKey',
      'authToken',
      'token',
      'NOTION_TOKEN',
      'clientSecret',
      'password',
      'Authorization',
    ]) {
      expect(isSensitiveLogKey(key), key).toBe(true);
    }
  });

  it('leaves ordinary fields and token counters alone', () => {
    for (const key of [
      'maxTokens',
      'inputTokens',
      'model',
      'provider',
      'activeProfileKey',
      'baseUrl',
    ]) {
      expect(isSensitiveLogKey(key), key).toBe(false);
    }
  });
});

describe('serializeLogArg', () => {
  it('redacts every provider key in the config.save payload', () => {
    const payload = {
      provider: 'anthropic',
      apiKey: '***',
      model: 'claude',
      maxTokens: 8192,
      profiles: {
        anthropic: { apiKey: 'sk-ant-api03-REALANTHROPICKEY0000', model: 'claude' },
        openai: { apiKey: 'sk-proj-REALOPENAIKEY000000000', model: 'gpt' },
        gemini: { apiKey: '', model: 'gemini' },
      },
    };

    const serialized = serializeLogArg(payload);
    expect(serialized).not.toContain('REALANTHROPICKEY');
    expect(serialized).not.toContain('REALOPENAIKEY');
    expect(serialized).toContain('[REDACTED]');
    expect(serialized).toContain('"maxTokens": 8192');
    expect(serialized).toContain('"model": "claude"');
    // Empty values stay visible: "not configured" is useful when debugging.
    expect(JSON.parse(serialized).profiles.gemini.apiKey).toBe('');
  });

  it('redacts MCP server env tokens and headers', () => {
    const serialized = serializeLogArg({
      name: 'Notion',
      env: { NOTION_TOKEN: 'ntn_secretvalue' },
      headers: { Authorization: 'Bearer abc' },
    });
    expect(serialized).not.toContain('ntn_secretvalue');
    expect(serialized).not.toContain('Bearer abc');
  });

  it('redacts keys embedded in error messages', () => {
    const error = new Error('401 for key sk-ant-api03-LEAKEDKEYLEAKEDKEY99');
    expect(serializeLogArg(error)).not.toContain('LEAKEDKEY');
  });
});

describe('redactSecretsInText', () => {
  it('masks well-known key formats inside free text', () => {
    const text = [
      'anthropic sk-ant-api03-abcdefghijklmnopqrstu',
      'openrouter sk-or-v1-abcdefghijklmnopqrstu',
      'google AIzaSyA1234567890abcdefghijklmnopqrstu',
      'slack xoxb-1234567890-abcdef',
      'header Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig',
    ].join('\n');
    const redacted = redactSecretsInText(text);
    expect(redacted).not.toMatch(/abcdefghijklmnopqrstu|xoxb-1234|eyJhbGci/);
    expect(redacted.match(/\[REDACTED\]/g)).toHaveLength(5);
  });

  it('does not touch normal text', () => {
    const text = 'task-runner finished in 3s, see sk-learn docs';
    expect(redactSecretsInText(text)).toBe(text);
  });
});
