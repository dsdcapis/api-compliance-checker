import { test } from 'node:test';
import assert from 'node:assert/strict';
import { compare, redactDocument, scanSensitive, toMarkdown } from '../src/engine/index.js';

const STANDARD = {
  openapi: '3.0.0',
  info: { title: 'Shipment API', version: '1.0.0' },
  paths: {
    '/shipments/v1/app/': {
      post: {
        operationId: 'createShipment',
        requestBody: { required: true, content: { 'application/json': { schema: { $ref: '#/components/schemas/ShipmentRequest' } } } },
        responses: {
          200: { description: 'ok', content: { 'application/json': { schema: { $ref: '#/components/schemas/ShipmentResponse' } } } },
          400: { description: 'bad', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
        },
      },
    },
    '/shipments/v1/app/{pro}': {
      get: {
        parameters: [
          { name: 'pro', in: 'path', required: true, schema: { type: 'string' } },
          { name: 'includeHistory', in: 'query', schema: { type: 'boolean' } },
        ],
        responses: { 200: { description: 'ok', content: { 'application/json': { schema: { $ref: '#/components/schemas/ShipmentResponse' } } } } },
      },
    },
  },
  components: {
    schemas: {
      ShipmentRequest: {
        type: 'object',
        required: ['proNumber', 'weight', 'function'],
        properties: {
          proNumber: { type: 'string', maxLength: 35 },
          weight: { type: 'number' },
          function: { type: 'string', enum: ['Create', 'Update'] },
          notes: { type: 'string' },
          shipper: { $ref: '#/components/schemas/Party' },
        },
      },
      Party: { type: 'object', required: ['name'], properties: { name: { type: 'string' }, accountNumber: { type: 'string' } } },
      ShipmentResponse: {
        type: 'object',
        required: ['proNumber', 'status'],
        properties: { proNumber: { type: 'string' }, status: { type: 'string', enum: ['Accepted', 'Rejected'] } },
      },
      Error: { type: 'object', properties: { code: { type: 'string' }, message: { type: 'string' } } },
    },
  },
};

const secured = (doc) => ({
  ...doc,
  servers: [{ url: 'https://api.carrier.example' }],
  security: [{ oauth: [] }],
  components: {
    ...doc.components,
    securitySchemes: { oauth: { type: 'oauth2', flows: { clientCredentials: { tokenUrl: 'https://auth.carrier.example/token', scopes: { 'shipments:write': 'write' } } } } },
  },
});
const clone = (o) => structuredClone(o);
const rules = (r, sev) => r.findings.filter((f) => !sev || f.severity === sev).map((f) => f.rule);

test('identical, secured implementation has no breaking issues', () => {
  const r = compare(STANDARD, secured(clone(STANDARD)));
  assert.equal(r.counts.breaking, 0, JSON.stringify(r.findings.filter((f) => f.severity === 'breaking'), null, 2));
  assert.notEqual(r.verdict, 'fail');
  assert.equal(r.coverage.operations.matched, 2);
});

test('missing operation is breaking', () => {
  const impl = secured(clone(STANDARD));
  delete impl.paths['/shipments/v1/app/{pro}'];
  const r = compare(STANDARD, impl);
  assert.equal(r.verdict, 'fail');
  assert.ok(rules(r, 'breaking').includes('missing-operation'));
});

test('renamed field is reported as terminology, not as missing + extra', () => {
  const impl = secured(clone(STANDARD));
  const p = impl.components.schemas.ShipmentRequest;
  p.properties.pro_number = p.properties.proNumber;
  delete p.properties.proNumber;
  p.required = ['pro_number', 'weight', 'function'];
  const r = compare(STANDARD, impl);
  const t = r.findings.find((f) => f.rule === 'field-name');
  assert.ok(t, 'expected terminology finding');
  assert.equal(t.severity, 'breaking');
  assert.equal(t.standard, 'proNumber');
  assert.equal(t.yours, 'pro_number');
  assert.ok(!r.findings.some((f) => f.rule === 'missing-required-field' && f.location.endsWith('proNumber')));
});

test('missing required vs optional fields, extra fields, and requirement changes', () => {
  const impl = secured(clone(STANDARD));
  const s = impl.components.schemas.ShipmentRequest;
  delete s.properties.weight;
  delete s.properties.notes;
  s.properties.internalCode = { type: 'string' };
  s.properties.trailerType = { type: 'string' };
  s.required = ['proNumber', 'function', 'trailerType'];
  impl.components.schemas.Party.required = ['name', 'accountNumber'];
  const r = compare(STANDARD, impl);
  const by = (rule, end) => r.findings.find((f) => f.rule === rule && f.location.endsWith(end));
  assert.equal(by('missing-required-field', 'weight')?.severity, 'breaking');
  assert.equal(by('missing-optional-field', 'notes')?.severity, 'warning');
  assert.equal(by('additional-field', 'internalCode')?.severity, 'info');
  assert.equal(by('additional-field', 'trailerType')?.severity, 'breaking');
  assert.equal(by('required-mismatch', 'accountNumber')?.severity, 'breaking');
});

test('type mismatch and enum differences respect request/response direction', () => {
  const impl = secured(clone(STANDARD));
  impl.components.schemas.ShipmentRequest.properties.weight = { type: 'string' };
  impl.components.schemas.ShipmentRequest.properties.function.enum = ['Create']; // drops a value clients may send
  impl.components.schemas.ShipmentResponse.properties.status.enum = ['Accepted', 'Rejected', 'Pending']; // returns unknown value
  const r = compare(STANDARD, impl);
  assert.ok(r.findings.some((f) => f.rule === 'type-mismatch' && f.severity === 'breaking'));
  assert.ok(r.findings.some((f) => f.rule === 'enum-value-missing' && f.severity === 'breaking' && f.standard === 'Update'));
  assert.ok(r.findings.some((f) => f.rule === 'enum-value-extra' && f.severity === 'breaking' && f.yours === 'Pending'));
});

test('misspelled enum value is terminology', () => {
  const impl = secured(clone(STANDARD));
  impl.components.schemas.ShipmentRequest.properties.function.enum = ['CREATE', 'Update'];
  const r = compare(STANDARD, impl);
  assert.ok(r.findings.some((f) => f.rule === 'enum-value-name' && f.standard === 'Create' && f.yours === 'CREATE'));
});

test('path prefix, renamed path param and changed success status', () => {
  const impl = secured(clone(STANDARD));
  impl.paths = {
    '/api/shipments/v1/app/': impl.paths['/shipments/v1/app/'],
    '/api/shipments/v1/app/{proNumber}': impl.paths['/shipments/v1/app/{pro}'],
  };
  impl.paths['/api/shipments/v1/app/{proNumber}'].get.parameters[0].name = 'proNumber';
  const post = impl.paths['/api/shipments/v1/app/'].post;
  post.responses = { 201: post.responses[200], 400: post.responses[400] };
  const r = compare(STANDARD, impl);
  assert.ok(rules(r).includes('path-prefix'));
  assert.ok(rules(r).includes('path-param-name'));
  assert.ok(!r.findings.some((f) => f.rule === 'missing-parameter'), 'renamed path param should still match');
  assert.ok(r.findings.some((f) => f.rule === 'success-status' && f.severity === 'breaking'));
});

test('query parameter made required is breaking', () => {
  const impl = secured(clone(STANDARD));
  impl.paths['/shipments/v1/app/{pro}'].get.parameters[1].required = true;
  const r = compare(STANDARD, impl);
  assert.ok(r.findings.some((f) => f.rule === 'required-mismatch' && f.severity === 'breaking' && f.location.includes('includeHistory')));
});

test('security baseline: no auth, plain http, api key in query', () => {
  const impl = clone(STANDARD);
  impl.servers = [{ url: 'http://api.carrier.example' }];
  let r = compare(STANDARD, impl);
  assert.ok(rules(r, 'breaking').includes('no-auth'));
  assert.ok(rules(r, 'breaking').includes('plain-http'));

  impl.components.securitySchemes = { key: { type: 'apiKey', in: 'query', name: 'api_key' } };
  impl.security = [{ key: [] }];
  r = compare(STANDARD, impl);
  assert.ok(rules(r, 'warning').includes('apikey-in-query'));
});

test('error handling baseline flags missing 404 for path-addressed resources', () => {
  const r = compare(STANDARD, secured(clone(STANDARD)));
  assert.ok(r.findings.some((f) => f.rule === 'missing-404' && f.location.includes('/shipments/v1/app/{pro}')));
});

test('swagger 2.0 and garbage are rejected cleanly', () => {
  assert.equal(compare(STANDARD, { swagger: '2.0', paths: {} }).verdict, 'fail');
  assert.equal(compare(STANDARD, 'just a string').verdict, 'fail');
  assert.equal(compare(STANDARD, null).verdict, 'fail');
});

test('cyclic schemas terminate', () => {
  const std = clone(STANDARD);
  std.components.schemas.Party.properties.parent = { $ref: '#/components/schemas/Party' };
  const impl = secured(clone(std));
  const r = compare(std, impl);
  assert.equal(r.counts.breaking, 0);
});

test('secrets and card numbers are detected and redacted', () => {
  const impl = secured(clone(STANDARD));
  impl.components.schemas.Party.properties.name.example = 'Acme';
  impl.components.schemas.Party.properties.token = { type: 'string', example: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdEFGHijklMNOP' };
  impl.components.schemas.Party.properties.card = { type: 'string', example: '4111 1111 1111 1111' };
  impl.components.schemas.Party.properties.password = { type: 'string', example: 'changeme' }; // placeholder, not flagged
  const hits = scanSensitive(impl);
  assert.deepEqual(hits.map((h) => h.kind).sort(), ['JSON Web Token', 'Payment card number']);
  const { doc, redactions } = redactDocument(impl, { maskServers: true });
  assert.equal(redactions, 2);
  const text = JSON.stringify(doc);
  assert.ok(!text.includes('4111 1111 1111 1111'));
  assert.ok(!text.includes('eyJhbGci'));
  assert.ok(!text.includes('api.carrier.example'));
  assert.ok(text.includes('Acme'));
});

test('markdown report renders', () => {
  const md = toMarkdown(compare(STANDARD, clone(STANDARD), { family: 'LTL' }));
  assert.match(md, /DSDC API compliance report — FAIL/);
  assert.match(md, /Breaking issues/);
});
