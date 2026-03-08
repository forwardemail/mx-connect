/* eslint no-console: 0*/

'use strict';

const mxConnect = require('../lib/mx-connect');
const dane = require('../lib/dane');
const nodeCrypto = require('crypto');

// Helper to create mock socket for testing
function createMockSocket(opts = {}) {
    const { EventEmitter } = require('events');
    const socket = new EventEmitter();
    socket.remoteAddress = opts.remoteAddress || '192.0.2.1';
    socket.localAddress = opts.localAddress || '192.0.2.100';
    socket.localPort = opts.localPort || 12345;
    socket.write = () => true;
    socket.end = () => socket.emit('end');
    socket.destroy = () => socket.emit('close');
    socket.pipe = () => socket;
    return socket;
}

/**
 * Test DANE module exports
 */
module.exports.daneModuleExports = test => {
    test.ok(dane.DANE_USAGE, 'DANE_USAGE should be exported');
    test.ok(dane.DANE_SELECTOR, 'DANE_SELECTOR should be exported');
    test.ok(dane.DANE_MATCHING_TYPE, 'DANE_MATCHING_TYPE should be exported');
    test.ok(dane.EMPTY_DANE_HANDLER, 'EMPTY_DANE_HANDLER should be exported');
    test.equal(typeof dane.hasNativeResolveTlsa, 'boolean', 'hasNativeResolveTlsa should be a boolean');
    test.equal(typeof dane.resolveTlsaRecords, 'function', 'resolveTlsaRecords should be a function');
    test.equal(typeof dane.verifyCertAgainstTlsa, 'function', 'verifyCertAgainstTlsa should be a function');
    test.equal(typeof dane.createDaneVerifier, 'function', 'createDaneVerifier should be a function');
    test.done();
};

/**
 * Test DANE usage constants
 */
module.exports.daneUsageConstants = test => {
    test.equal(dane.DANE_USAGE.PKIX_TA, 0, 'PKIX_TA should be 0');
    test.equal(dane.DANE_USAGE.PKIX_EE, 1, 'PKIX_EE should be 1');
    test.equal(dane.DANE_USAGE.DANE_TA, 2, 'DANE_TA should be 2');
    test.equal(dane.DANE_USAGE.DANE_EE, 3, 'DANE_EE should be 3');
    test.done();
};

/**
 * Test DANE selector constants
 */
module.exports.daneSelectorConstants = test => {
    test.equal(dane.DANE_SELECTOR.FULL_CERT, 0, 'FULL_CERT should be 0');
    test.equal(dane.DANE_SELECTOR.SPKI, 1, 'SPKI should be 1');
    test.done();
};

/**
 * Test DANE matching type constants
 */
module.exports.daneMatchingTypeConstants = test => {
    test.equal(dane.DANE_MATCHING_TYPE.FULL, 0, 'FULL should be 0');
    test.equal(dane.DANE_MATCHING_TYPE.SHA256, 1, 'SHA256 should be 1');
    test.equal(dane.DANE_MATCHING_TYPE.SHA512, 2, 'SHA512 should be 2');
    test.done();
};

/**
 * Test hashCertData function with SHA-256
 */
module.exports.hashCertDataSha256 = test => {
    const testData = Buffer.from('test certificate data');
    const expectedHash = nodeCrypto.createHash('sha256').update(testData).digest();
    const result = dane.hashCertData(testData, dane.DANE_MATCHING_TYPE.SHA256);
    test.ok(Buffer.isBuffer(result), 'Result should be a Buffer');
    test.ok(expectedHash.equals(result), 'SHA-256 hash should match');
    test.done();
};

/**
 * Test hashCertData function with SHA-512
 */
module.exports.hashCertDataSha512 = test => {
    const testData = Buffer.from('test certificate data');
    const expectedHash = nodeCrypto.createHash('sha512').update(testData).digest();
    const result = dane.hashCertData(testData, dane.DANE_MATCHING_TYPE.SHA512);
    test.ok(Buffer.isBuffer(result), 'Result should be a Buffer');
    test.ok(expectedHash.equals(result), 'SHA-512 hash should match');
    test.done();
};

/**
 * Test hashCertData function with full data (no hash)
 */
module.exports.hashCertDataFull = test => {
    const testData = Buffer.from('test certificate data');
    const result = dane.hashCertData(testData, dane.DANE_MATCHING_TYPE.FULL);
    test.ok(Buffer.isBuffer(result), 'Result should be a Buffer');
    test.ok(testData.equals(result), 'Full data should be returned unchanged');
    test.done();
};

/**
 * Test hashCertData with null input
 */
module.exports.hashCertDataNull = test => {
    const result = dane.hashCertData(null, dane.DANE_MATCHING_TYPE.SHA256);
    test.equal(result, null, 'Result should be null for null input');
    test.done();
};

/**
 * Test verifyCertAgainstTlsa with no records
 */
module.exports.verifyCertNoRecords = test => {
    const result = dane.verifyCertAgainstTlsa({}, []);
    test.equal(result.valid, true, 'Should be valid when no records exist');
    test.equal(result.noRecords, true, 'Should indicate no records');
    test.equal(result.matchedRecord, null, 'Should have no matched record');
    test.done();
};

/**
 * Test verifyCertAgainstTlsa with no certificate
 */
module.exports.verifyCertNoCert = test => {
    const tlsaRecords = [{ usage: 3, selector: 1, mtype: 1, cert: Buffer.alloc(32) }];
    const result = dane.verifyCertAgainstTlsa(null, tlsaRecords);
    test.equal(result.valid, false, 'Should be invalid when no certificate');
    test.ok(result.error, 'Should have an error message');
    test.done();
};

/**
 * Test createDaneVerifier returns a function
 */
module.exports.createDaneVerifierReturnsFunction = test => {
    const verifier = dane.createDaneVerifier([], {});
    test.equal(typeof verifier, 'function', 'Should return a function');
    test.done();
};

/**
 * Test createDaneVerifier with no records returns undefined (success)
 */
module.exports.createDaneVerifierNoRecords = test => {
    const verifier = dane.createDaneVerifier([], {});
    const result = verifier('example.com', {});
    test.equal(result, undefined, 'Should return undefined (success) when no records');
    test.done();
};

/**
 * Test EMPTY_DANE_HANDLER
 */
module.exports.emptyDaneHandler = async test => {
    test.equal(dane.EMPTY_DANE_HANDLER.enabled, false, 'Should be disabled by default');
    const records = await dane.EMPTY_DANE_HANDLER.resolveTlsa('test.example.com');
    test.deepEqual(records, [], 'Should return empty array');
    test.done();
};

/**
 * Test mx-connect exports DANE module
 */
module.exports.mxConnectExportsDane = test => {
    test.ok(mxConnect.dane, 'mx-connect should export dane module');
    test.equal(typeof mxConnect.dane.resolveTlsaRecords, 'function', 'Should export resolveTlsaRecords');
    test.equal(typeof mxConnect.dane.verifyCertAgainstTlsa, 'function', 'Should export verifyCertAgainstTlsa');
    test.done();
};

/**
 * Test DANE with custom resolver using mock socket
 */
module.exports.daneWithCustomResolver = test => {
    let tlsaLookupCalled = false;

    const mockResolveTlsa = async () => {
        tlsaLookupCalled = true;
        // Return empty array to simulate no DANE records
        return [];
    };

    mxConnect(
        {
            target: 'test.example.com',
            mx: [
                {
                    exchange: 'mail.example.com',
                    priority: 10,
                    A: ['192.0.2.1'],
                    AAAA: []
                }
            ],
            dane: {
                enabled: true,
                resolveTlsa: mockResolveTlsa,
                logger: () => {}
            },
            connectHook(delivery, options, callback) {
                options.socket = createMockSocket({ remoteAddress: options.host });
                return callback();
            }
        },
        (err, connection) => {
            test.ifError(err);
            test.ok(connection, 'Connection should exist');
            test.ok(connection.socket, 'Connection should have socket');
            test.ok(tlsaLookupCalled, 'Custom resolveTlsa should have been called');
            test.done();
        }
    );
};

/**
 * Test DANE with custom resolver returning TLSA records
 */
module.exports.daneWithTlsaRecords = test => {
    let logMessages = [];

    // Mock TLSA records (these won't match the actual certificate, but tests the flow)
    const mockTlsaRecords = [
        {
            usage: 3, // DANE-EE
            selector: 1, // SPKI
            mtype: 1, // SHA-256
            cert: Buffer.alloc(32, 0xff), // Fake hash
            ttl: 3600
        }
    ];

    const mockResolveTlsa = async () => mockTlsaRecords;

    mxConnect(
        {
            target: 'test.example.com',
            mx: [
                {
                    exchange: 'mail.example.com',
                    priority: 10,
                    A: ['192.0.2.1'],
                    AAAA: []
                }
            ],
            dane: {
                enabled: true,
                resolveTlsa: mockResolveTlsa,
                verify: false, // Don't enforce verification (cert won't match mock)
                logger: logObj => {
                    logMessages.push(logObj);
                }
            },
            connectHook(delivery, options, callback) {
                options.socket = createMockSocket({ remoteAddress: options.host });
                return callback();
            }
        },
        (err, connection) => {
            test.ifError(err);
            test.ok(connection, 'Connection should exist');
            test.ok(connection.socket, 'Connection should have socket');

            // Check that TLSA records were found
            const tlsaFoundLog = logMessages.find(log => log.msg === 'TLSA records found');
            test.ok(tlsaFoundLog, 'Should log TLSA records found');
            test.equal(tlsaFoundLog.recordCount, 1, 'Should have 1 TLSA record');

            // Check that DANE was enabled for connection
            const daneEnabledLog = logMessages.find(log => log.msg === 'DANE enabled for connection');
            test.ok(daneEnabledLog, 'Should log DANE enabled for connection');

            // Check connection has DANE properties
            test.ok(connection.daneEnabled, 'Connection should have daneEnabled flag');
            test.ok(connection.tlsaRecords, 'Connection should have tlsaRecords');
            test.equal(connection.tlsaRecords.length, 1, 'Should have 1 TLSA record');

            test.done();
        }
    );
};

/**
 * Test DANE with resolver that throws error (verify mode rejects connection)
 */
module.exports.daneResolverError = test => {
    const mockResolveTlsa = async () => {
        const err = new Error('DNS lookup failed');
        err.code = 'ESERVFAIL';
        throw err;
    };

    mxConnect(
        {
            target: 'test.example.com',
            mx: [
                {
                    exchange: 'mail.example.com',
                    priority: 10,
                    A: ['192.0.2.1'],
                    AAAA: []
                }
            ],
            dane: {
                enabled: true,
                resolveTlsa: mockResolveTlsa,
                logger: () => {}
            },
            connectHook(delivery, options, callback) {
                options.socket = createMockSocket({ remoteAddress: options.host });
                return callback();
            }
        },
        (err, connection) => {
            test.ok(err, 'Should return an error when DANE lookup fails in verify mode');
            test.ok(!connection, 'Connection should not exist');
            test.ok(err.message.includes('DANE TLSA lookup failed'), 'Error should mention DANE lookup failure');
            test.equal(err.category, 'dane', 'Error category should be dane');
            test.done();
        }
    );
};

/**
 * Test DANE with resolver error and verify:false allows connection
 */
module.exports.daneResolverErrorVerifyFalse = test => {
    let logMessages = [];

    const mockResolveTlsa = async () => {
        const err = new Error('DNS lookup failed');
        err.code = 'ESERVFAIL';
        throw err;
    };

    mxConnect(
        {
            target: 'test.example.com',
            mx: [
                {
                    exchange: 'mail.example.com',
                    priority: 10,
                    A: ['192.0.2.1'],
                    AAAA: []
                }
            ],
            dane: {
                enabled: true,
                verify: false,
                resolveTlsa: mockResolveTlsa,
                logger: logObj => {
                    logMessages.push(logObj);
                }
            },
            connectHook(delivery, options, callback) {
                options.socket = createMockSocket({ remoteAddress: options.host });
                return callback();
            }
        },
        (err, connection) => {
            test.ifError(err);
            test.ok(connection, 'Connection should exist when verify is false');
            test.ok(connection.socket, 'Connection should have socket');

            // Check that TLSA lookup failure was logged
            const failLog = logMessages.find(log => log.msg === 'TLSA lookup failed');
            test.ok(failLog, 'Should log TLSA lookup failure');
            test.ok(failLog.error, 'Should include error message');

            test.done();
        }
    );
};

/**
 * Test DANE with NODATA response (no records exist)
 */
module.exports.daneNoDataResponse = test => {
    const mockResolveTlsa = async () => {
        const err = new Error('No data');
        err.code = 'ENODATA';
        throw err;
    };

    mxConnect(
        {
            target: 'test.example.com',
            mx: [
                {
                    exchange: 'mail.example.com',
                    priority: 10,
                    A: ['192.0.2.1'],
                    AAAA: []
                }
            ],
            dane: {
                enabled: true,
                resolveTlsa: mockResolveTlsa,
                logger: () => {}
            },
            connectHook(delivery, options, callback) {
                options.socket = createMockSocket({ remoteAddress: options.host });
                return callback();
            }
        },
        (err, connection) => {
            test.ifError(err);
            test.ok(connection, 'Connection should exist');
            test.ok(connection.socket, 'Connection should have socket');
            // Should succeed - NODATA means no DANE records, not an error
            test.done();
        }
    );
};

/**
 * Test DANE explicitly disabled
 */
module.exports.daneExplicitlyDisabled = test => {
    let tlsaLookupCalled = false;

    const mockResolveTlsa = async () => {
        tlsaLookupCalled = true;
        return [];
    };

    mxConnect(
        {
            target: 'test.example.com',
            mx: [
                {
                    exchange: 'mail.example.com',
                    priority: 10,
                    A: ['192.0.2.1'],
                    AAAA: []
                }
            ],
            dane: {
                enabled: false,
                resolveTlsa: mockResolveTlsa
            },
            connectHook(delivery, options, callback) {
                options.socket = createMockSocket({ remoteAddress: options.host });
                return callback();
            }
        },
        (err, connection) => {
            test.ifError(err);
            test.ok(connection, 'Connection should exist');
            test.ok(connection.socket, 'Connection should have socket');
            test.ok(!tlsaLookupCalled, 'resolveTlsa should not be called when DANE is disabled');
            test.done();
        }
    );
};

/**
 * Test resolveTlsaRecords with custom resolver
 */
module.exports.resolveTlsaRecordsCustomResolver = async test => {
    const mockRecords = [{ usage: 3, selector: 1, mtype: 1, cert: Buffer.alloc(32) }];
    const mockResolver = async tlsaName => {
        test.equal(tlsaName, '_25._tcp.mail.example.com', 'Should format TLSA name correctly');
        return mockRecords;
    };

    const records = await dane.resolveTlsaRecords('mail.example.com', 25, { resolveTlsa: mockResolver });
    test.deepEqual(records, mockRecords, 'Should return records from custom resolver');
    test.done();
};

/**
 * Test resolveTlsaRecords handles ENODATA gracefully
 */
module.exports.resolveTlsaRecordsNoData = async test => {
    const mockResolver = async () => {
        const err = new Error('No data');
        err.code = 'ENODATA';
        throw err;
    };

    const records = await dane.resolveTlsaRecords('mail.example.com', 25, { resolveTlsa: mockResolver });
    test.deepEqual(records, [], 'Should return empty array for ENODATA');
    test.done();
};

/**
 * Test resolveTlsaRecords handles ENOTFOUND gracefully
 */
module.exports.resolveTlsaRecordsNotFound = async test => {
    const mockResolver = async () => {
        const err = new Error('Not found');
        err.code = 'ENOTFOUND';
        throw err;
    };

    const records = await dane.resolveTlsaRecords('mail.example.com', 25, { resolveTlsa: mockResolver });
    test.deepEqual(records, [], 'Should return empty array for ENOTFOUND');
    test.done();
};

/**
 * Test resolveTlsaRecords propagates other errors
 */
module.exports.resolveTlsaRecordsOtherError = async test => {
    const mockResolver = async () => {
        const err = new Error('Server failure');
        err.code = 'ESERVFAIL';
        throw err;
    };

    try {
        await dane.resolveTlsaRecords('mail.example.com', 25, { resolveTlsa: mockResolver });
        test.ok(false, 'Should have thrown an error');
    } catch (err) {
        test.equal(err.code, 'ESERVFAIL', 'Should propagate non-NODATA errors');
    }
    test.done();
};

/**
 * Test hasNativeResolveTlsa detection
 */
module.exports.hasNativeResolveTlsaDetection = test => {
    const dns = require('dns');
    const expected = typeof dns.resolveTlsa === 'function';
    test.equal(dane.hasNativeResolveTlsa, expected, 'hasNativeResolveTlsa should match actual dns module');
    test.done();
};

/**
 * Test DANE with pre-resolved MX that includes TLSA records
 */
module.exports.daneWithPreresolvedMx = test => {
    let logMessages = [];

    const mockTlsaRecords = [
        {
            usage: 3,
            selector: 1,
            mtype: 1,
            cert: Buffer.alloc(32, 0xaa)
        }
    ];

    mxConnect(
        {
            target: 'test.example.com',
            mx: [
                {
                    exchange: 'mail.example.com',
                    priority: 10,
                    A: ['192.0.2.1'],
                    AAAA: [],
                    tlsaRecords: mockTlsaRecords
                }
            ],
            dane: {
                enabled: true,
                verify: false,
                logger: logObj => {
                    logMessages.push(logObj);
                }
            },
            connectHook(delivery, options, callback) {
                options.socket = createMockSocket({ remoteAddress: options.host });
                return callback();
            }
        },
        (err, connection) => {
            test.ifError(err);
            test.ok(connection, 'Connection should exist');
            test.ok(connection.socket, 'Connection should have socket');

            // TLSA records should be passed through from pre-resolved MX
            test.ok(connection.tlsaRecords, 'Connection should have tlsaRecords');
            test.equal(connection.tlsaRecords.length, 1, 'Should have 1 TLSA record');

            test.done();
        }
    );
};

/**
 * Test DANE stays disabled without explicit enabled:true
 */
module.exports.daneAutoDetectNoResolver = test => {
    let tlsaLookupCalled = false;

    mxConnect(
        {
            target: 'test.example.com',
            mx: [
                {
                    exchange: 'mail.example.com',
                    priority: 10,
                    A: ['192.0.2.1'],
                    AAAA: []
                }
            ],
            dane: {
                // enabled not set - should default to false
                resolveTlsa: async () => {
                    tlsaLookupCalled = true;
                    return [];
                },
                logger: () => {}
            },
            connectHook(delivery, options, callback) {
                options.socket = createMockSocket({ remoteAddress: options.host });
                return callback();
            }
        },
        (err, connection) => {
            test.ifError(err);
            test.ok(connection, 'Connection should exist');
            test.ok(connection.socket, 'Connection should have socket');
            test.ok(!tlsaLookupCalled, 'resolveTlsa should not be called when enabled is not set');
            test.done();
        }
    );
};

/**
 * Test extractSPKI with malformed certificate (Issue #1)
 */
module.exports.extractSPKIMalformedCert = test => {
    // Test with null
    let result = dane.extractSPKI(null);
    test.equal(result, null, 'Should return null for null certificate');

    // Test with empty object
    result = dane.extractSPKI({});
    test.equal(result, null, 'Should return null for empty certificate');

    // Test with invalid publicKey
    result = dane.extractSPKI({ publicKey: 'invalid-key-data' });
    test.equal(result, null, 'Should return null for invalid publicKey');

    // Test with malformed publicKey buffer
    result = dane.extractSPKI({ publicKey: Buffer.from('invalid') });
    test.equal(result, null, 'Should return null for malformed publicKey buffer');

    test.done();
};

/**
 * Test getCertData with malformed certificate (Issue #2)
 */
module.exports.getCertDataMalformedCert = test => {
    // Test with null
    let result = dane.getCertData(null, dane.DANE_SELECTOR.FULL_CERT);
    test.equal(result, null, 'Should return null for null certificate');

    // Test with empty object (no raw property)
    result = dane.getCertData({}, dane.DANE_SELECTOR.FULL_CERT);
    test.equal(result, null, 'Should return null for certificate without raw');

    // Test with SPKI selector on malformed cert
    result = dane.getCertData({ publicKey: 'invalid' }, dane.DANE_SELECTOR.SPKI);
    test.equal(result, null, 'Should return null for malformed certificate with SPKI selector');

    test.done();
};

/**
 * Test verifyCertAgainstTlsa with malformed TLSA records (Issue #4)
 */
module.exports.verifyCertMalformedTlsaRecords = test => {
    const mockCert = {
        raw: Buffer.from('test-cert-data'),
        publicKey: null
    };

    // Test with record missing cert field
    const recordsNoCert = [{ usage: 3, selector: 0, mtype: 1 }];
    let result = dane.verifyCertAgainstTlsa(mockCert, recordsNoCert);
    test.equal(result.valid, false, 'Should be invalid when record has no cert field');

    // Test with invalid usage value (should not crash)
    const recordsInvalidUsage = [{ usage: 99, selector: 0, mtype: 1, cert: Buffer.alloc(32) }];
    result = dane.verifyCertAgainstTlsa(mockCert, recordsInvalidUsage);
    test.equal(result.valid, false, 'Should be invalid for unknown usage type');

    // Test with invalid selector value (should not crash)
    const recordsInvalidSelector = [{ usage: 3, selector: 99, mtype: 1, cert: Buffer.alloc(32) }];
    result = dane.verifyCertAgainstTlsa(mockCert, recordsInvalidSelector);
    test.equal(result.valid, false, 'Should be invalid for unknown selector');

    test.done();
};

/**
 * Test createDaneVerifier catches exceptions (Issue #1, #2, #4)
 */
module.exports.createDaneVerifierCatchesExceptions = test => {
    const tlsaRecords = [
        {
            usage: 3,
            selector: 1,
            mtype: 1,
            cert: Buffer.alloc(32, 0xff)
        }
    ];

    const verifier = dane.createDaneVerifier(tlsaRecords, { verify: true });

    // Test with malformed certificate - should not throw
    let result;
    try {
        result = verifier('example.com', { publicKey: 'invalid' });
        test.ok(true, 'Should not throw for malformed certificate');
    } catch (err) {
        test.ok(false, 'Should not throw exception: ' + err.message);
    }

    // Result should be an error (verification failed), not an exception
    test.ok(result instanceof Error || result === undefined, 'Should return error or undefined, not throw');

    test.done();
};

/**
 * Test isNoRecordsError helper function
 */
module.exports.isNoRecordsErrorHelper = test => {
    test.ok(dane.isNoRecordsError, 'isNoRecordsError should be exported');
    test.equal(dane.isNoRecordsError('ENODATA'), true, 'ENODATA should be a no-records error');
    test.equal(dane.isNoRecordsError('ENOTFOUND'), true, 'ENOTFOUND should be a no-records error');
    test.equal(dane.isNoRecordsError('ENOENT'), true, 'ENOENT should be a no-records error');
    test.equal(dane.isNoRecordsError('ESERVFAIL'), false, 'ESERVFAIL should not be a no-records error');
    test.equal(dane.isNoRecordsError('ETIMEDOUT'), false, 'ETIMEDOUT should not be a no-records error');
    test.equal(dane.isNoRecordsError(undefined), false, 'undefined should not be a no-records error');
    test.done();
};

/**
 * Test hasNativePromiseResolveTlsa detection
 */
module.exports.hasNativePromiseResolveTlsaDetection = test => {
    const dns = require('dns');
    const expected = dns.promises && typeof dns.promises.resolveTlsa === 'function';
    test.equal(dane.hasNativePromiseResolveTlsa, expected, 'hasNativePromiseResolveTlsa should match actual dns.promises module');
    test.done();
};

/**
 * Test verifyCertAgainstTlsa with DANE-TA without chain (Issue #3)
 */
module.exports.verifyCertDaneTaWithoutChain = test => {
    const mockCert = {
        raw: Buffer.from('test-cert-data'),
        publicKey: null
    };

    // DANE-TA record without chain should fail with informative error
    const daneTeRecords = [
        {
            usage: 2, // DANE-TA
            selector: 0,
            mtype: 1,
            cert: Buffer.alloc(32, 0xaa)
        }
    ];

    const result = dane.verifyCertAgainstTlsa(mockCert, daneTeRecords);
    test.equal(result.valid, false, 'Should be invalid when DANE-TA has no chain');
    test.ok(result.error, 'Should have error message');
    test.ok(result.error.includes('chain'), 'Error should mention chain requirement');

    test.done();
};

/**
 * Test verifyCertAgainstTlsa with PKIX-TA without chain (Issue #3)
 */
module.exports.verifyCertPkixTaWithoutChain = test => {
    const mockCert = {
        raw: Buffer.from('test-cert-data'),
        publicKey: null
    };

    // PKIX-TA record without chain should fail with informative error
    const pkixTaRecords = [
        {
            usage: 0, // PKIX-TA
            selector: 0,
            mtype: 1,
            cert: Buffer.alloc(32, 0xaa)
        }
    ];

    const result = dane.verifyCertAgainstTlsa(mockCert, pkixTaRecords);
    test.equal(result.valid, false, 'Should be invalid when PKIX-TA has no chain');
    test.ok(result.error, 'Should have error message');
    test.ok(result.error.includes('chain'), 'Error should mention chain requirement');

    test.done();
};

/**
 * Test hashCertData handles exceptions gracefully
 */
module.exports.hashCertDataHandlesExceptions = test => {
    // Test with invalid data type that might cause issues
    const result = dane.hashCertData(undefined, dane.DANE_MATCHING_TYPE.SHA256);
    test.equal(result, null, 'Should return null for undefined data');

    test.done();
};

/**
 * Test verifyCertAgainstTlsa with string cert data (hex encoded)
 */
module.exports.verifyCertWithStringCertData = test => {
    const testData = Buffer.from('test-cert-data');
    const hash = nodeCrypto.createHash('sha256').update(testData).digest();

    const mockCert = {
        raw: testData
    };

    // Record with hex-encoded cert data
    const records = [
        {
            usage: 3,
            selector: 0,
            mtype: 1,
            cert: hash.toString('hex') // String instead of Buffer
        }
    ];

    const result = dane.verifyCertAgainstTlsa(mockCert, records);
    test.equal(result.valid, true, 'Should handle hex-encoded cert data');
    test.equal(result.usage, 'DANE-EE', 'Should report DANE-EE usage');

    test.done();
};

/**
 * Test extractSPKI with raw peer certificate (.pubkey Buffer)
 *
 * Raw peer certs from tls.getPeerCertificate() have .pubkey (Buffer)
 * containing the SubjectPublicKeyInfo in DER format. The old code
 * checked .publicKey (undefined on raw certs) and returned null.
 */
module.exports.extractSPKIRawPeerCert = test => {
    const { publicKey } = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const spkiDer = publicKey.export({ type: 'spki', format: 'der' });

    // Simulate a raw peer cert from tls.getPeerCertificate()
    const rawPeerCert = {
        raw: Buffer.from('fake-cert-der'),
        pubkey: spkiDer
        // Note: no .publicKey property — this is what raw peer certs look like
    };

    const result = dane.extractSPKI(rawPeerCert);
    test.ok(Buffer.isBuffer(result), 'Should return a Buffer');
    test.ok(spkiDer.equals(result), 'Should return the .pubkey Buffer as SPKI');
    test.equal(result.length, spkiDer.length, 'Buffer length should match SPKI DER');
    test.done();
};

/**
 * Test extractSPKI with X509Certificate object (.publicKey KeyObject)
 *
 * X509Certificate objects have .publicKey as a KeyObject. The old code
 * called crypto.createPublicKey(KeyObject) which throws "Invalid key
 * object type public, expected private". The fix calls .export() directly.
 */
module.exports.extractSPKIX509Certificate = test => {
    const { publicKey } = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const spkiDer = publicKey.export({ type: 'spki', format: 'der' });

    // Simulate an X509Certificate object: .publicKey is a KeyObject.
    // The old code called crypto.createPublicKey(KeyObject) which throws
    // "Invalid key object type public, expected private".
    const mockX509 = {
        publicKey, // KeyObject (PublicKeyObject)
        raw: Buffer.from('fake-cert-der')
    };

    const result = dane.extractSPKI(mockX509);
    test.ok(Buffer.isBuffer(result), 'Should return a Buffer');
    test.ok(spkiDer.equals(result), 'Should match the exported SPKI DER');
    test.done();
};

/**
 * Test extractSPKI with PEM-encoded public key string
 */
module.exports.extractSPKIPemString = test => {
    const { publicKey } = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const spkiDer = publicKey.export({ type: 'spki', format: 'der' });
    const spkiPem = publicKey.export({ type: 'spki', format: 'pem' });

    const mockCert = {
        publicKey: spkiPem // PEM string
    };

    const result = dane.extractSPKI(mockCert);
    test.ok(Buffer.isBuffer(result), 'Should return a Buffer');
    test.ok(spkiDer.equals(result), 'PEM extraction should match DER');
    test.done();
};

/**
 * Test extractSPKI returns consistent results for raw peer cert and X509Certificate
 *
 * Both cert representations must produce the same SPKI DER output.
 */
module.exports.extractSPKIConsistentAcrossCertTypes = test => {
    const { publicKey } = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const spkiDer = publicKey.export({ type: 'spki', format: 'der' });

    // Simulate raw peer cert
    const rawPeerCert = { pubkey: spkiDer };

    // Simulate X509Certificate
    const x509Cert = { publicKey };

    const result1 = dane.extractSPKI(rawPeerCert);
    const result2 = dane.extractSPKI(x509Cert);

    test.ok(Buffer.isBuffer(result1), 'Raw peer cert result should be a Buffer');
    test.ok(Buffer.isBuffer(result2), 'X509Certificate result should be a Buffer');
    test.ok(result1.equals(result2), 'Both cert types should produce identical SPKI');
    test.done();
};

/**
 * Test full DANE-EE (usage=3) SPKI SHA-256 verification with raw peer cert
 *
 * This is the most common DANE configuration (e.g., mx1.forwardemail.net).
 * Verifies the complete pipeline: extractSPKI → hash → compare against TLSA.
 */
module.exports.verifyCertDaneEESPKISha256RawPeerCert = test => {
    const { publicKey } = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const spkiDer = publicKey.export({ type: 'spki', format: 'der' });
    const spkiHash = nodeCrypto.createHash('sha256').update(spkiDer).digest();

    // Simulate raw peer cert
    const rawPeerCert = {
        raw: Buffer.from('fake-cert-der'),
        pubkey: spkiDer
    };

    // TLSA record: usage=3 (DANE-EE), selector=1 (SPKI), mtype=1 (SHA-256)
    const tlsaRecords = [{
        usage: 3,
        selector: 1,
        mtype: 1,
        cert: spkiHash
    }];

    const result = dane.verifyCertAgainstTlsa(rawPeerCert, tlsaRecords);
    test.equal(result.valid, true, 'DANE-EE SPKI SHA-256 should verify against raw peer cert');
    test.equal(result.usage, 'DANE-EE', 'Should report DANE-EE usage');
    test.ok(result.matchedRecord, 'Should have a matched record');
    test.equal(result.matchedRecord.usage, 3, 'Matched record usage should be 3');
    test.equal(result.matchedRecord.selector, 1, 'Matched record selector should be 1');
    test.done();
};

/**
 * Test full DANE-EE (usage=3) SPKI SHA-256 verification with X509Certificate
 */
module.exports.verifyCertDaneEESPKISha256X509Certificate = test => {
    const { publicKey } = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const spkiDer = publicKey.export({ type: 'spki', format: 'der' });
    const spkiHash = nodeCrypto.createHash('sha256').update(spkiDer).digest();

    // Simulate X509Certificate
    const x509Cert = {
        raw: Buffer.from('fake-cert-der'),
        publicKey // KeyObject
    };

    const tlsaRecords = [{
        usage: 3,
        selector: 1,
        mtype: 1,
        cert: spkiHash
    }];

    const result = dane.verifyCertAgainstTlsa(x509Cert, tlsaRecords);
    test.equal(result.valid, true, 'DANE-EE SPKI SHA-256 should verify against X509Certificate');
    test.equal(result.usage, 'DANE-EE', 'Should report DANE-EE usage');
    test.done();
};

/**
 * Test DANE-EE SPKI SHA-512 verification
 */
module.exports.verifyCertDaneEESPKISha512 = test => {
    const { publicKey } = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const spkiDer = publicKey.export({ type: 'spki', format: 'der' });
    const spkiHash = nodeCrypto.createHash('sha512').update(spkiDer).digest();

    const rawPeerCert = {
        raw: Buffer.from('fake-cert-der'),
        pubkey: spkiDer
    };

    const tlsaRecords = [{
        usage: 3,
        selector: 1,
        mtype: 2, // SHA-512
        cert: spkiHash
    }];

    const result = dane.verifyCertAgainstTlsa(rawPeerCert, tlsaRecords);
    test.equal(result.valid, true, 'DANE-EE SPKI SHA-512 should verify');
    test.equal(result.usage, 'DANE-EE', 'Should report DANE-EE usage');
    test.done();
};

/**
 * Test DANE-EE SPKI full match (mtype=0, no hash)
 */
module.exports.verifyCertDaneEESPKIFullMatch = test => {
    const { publicKey } = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const spkiDer = publicKey.export({ type: 'spki', format: 'der' });

    const rawPeerCert = {
        raw: Buffer.from('fake-cert-der'),
        pubkey: spkiDer
    };

    const tlsaRecords = [{
        usage: 3,
        selector: 1,
        mtype: 0, // Full match
        cert: spkiDer
    }];

    const result = dane.verifyCertAgainstTlsa(rawPeerCert, tlsaRecords);
    test.equal(result.valid, true, 'DANE-EE SPKI full match should verify');
    test.done();
};

/**
 * Test DANE-EE verification fails with wrong TLSA hash
 */
module.exports.verifyCertDaneEEWrongHash = test => {
    const { publicKey } = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const spkiDer = publicKey.export({ type: 'spki', format: 'der' });

    const rawPeerCert = {
        raw: Buffer.from('fake-cert-der'),
        pubkey: spkiDer
    };

    const tlsaRecords = [{
        usage: 3,
        selector: 1,
        mtype: 1,
        cert: Buffer.alloc(32, 0xAB) // Wrong hash
    }];

    const result = dane.verifyCertAgainstTlsa(rawPeerCert, tlsaRecords);
    test.equal(result.valid, false, 'Should fail with wrong TLSA hash');
    test.ok(result.error, 'Should have error message');
    test.ok(result.error.includes('did not match'), 'Error should mention no match');
    test.done();
};

/**
 * Test DANE-EE full cert (selector=0) verification
 */
module.exports.verifyCertDaneEEFullCertSelector = test => {
    const certDer = Buffer.from('test-certificate-data-in-der-format');
    const certHash = nodeCrypto.createHash('sha256').update(certDer).digest();

    const rawPeerCert = {
        raw: certDer,
        pubkey: Buffer.from('fake-spki')
    };

    const tlsaRecords = [{
        usage: 3,
        selector: 0, // Full cert
        mtype: 1,    // SHA-256
        cert: certHash
    }];

    const result = dane.verifyCertAgainstTlsa(rawPeerCert, tlsaRecords);
    test.equal(result.valid, true, 'DANE-EE full cert SHA-256 should verify');
    test.equal(result.usage, 'DANE-EE', 'Should report DANE-EE usage');
    test.done();
};

/**
 * Test PKIX-EE (usage=1) SPKI verification with raw peer cert
 */
module.exports.verifyCertPkixEESPKI = test => {
    const { publicKey } = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const spkiDer = publicKey.export({ type: 'spki', format: 'der' });
    const spkiHash = nodeCrypto.createHash('sha256').update(spkiDer).digest();

    const rawPeerCert = {
        raw: Buffer.from('fake-cert-der'),
        pubkey: spkiDer
    };

    const tlsaRecords = [{
        usage: 1, // PKIX-EE
        selector: 1,
        mtype: 1,
        cert: spkiHash
    }];

    const result = dane.verifyCertAgainstTlsa(rawPeerCert, tlsaRecords);
    test.equal(result.valid, true, 'PKIX-EE SPKI SHA-256 should verify');
    test.equal(result.usage, 'PKIX-EE', 'Should report PKIX-EE usage');
    test.done();
};

/**
 * Test createDaneVerifier end-to-end with correct TLSA (should pass)
 */
module.exports.createDaneVerifierE2ECorrectTlsa = test => {
    const { publicKey } = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const spkiDer = publicKey.export({ type: 'spki', format: 'der' });
    const spkiHash = nodeCrypto.createHash('sha256').update(spkiDer).digest();

    const rawPeerCert = {
        raw: Buffer.from('fake-cert-der'),
        pubkey: spkiDer
    };

    const tlsaRecords = [{
        usage: 3,
        selector: 1,
        mtype: 1,
        cert: spkiHash
    }];

    let logMessages = [];
    const verifier = dane.createDaneVerifier(tlsaRecords, {
        verify: true,
        logger: entry => logMessages.push(entry)
    });

    const result = verifier('mail.example.com', rawPeerCert);
    test.equal(result, undefined, 'Should return undefined (success) for matching TLSA');

    const successLog = logMessages.find(l => l.msg === 'DANE verification succeeded');
    test.ok(successLog, 'Should log DANE verification succeeded');
    test.equal(successLog.usage, 'DANE-EE', 'Log should report DANE-EE');
    test.done();
};

/**
 * Test createDaneVerifier end-to-end with wrong TLSA (should fail)
 */
module.exports.createDaneVerifierE2EWrongTlsa = test => {
    const { publicKey } = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const spkiDer = publicKey.export({ type: 'spki', format: 'der' });

    const rawPeerCert = {
        raw: Buffer.from('fake-cert-der'),
        pubkey: spkiDer
    };

    const tlsaRecords = [{
        usage: 3,
        selector: 1,
        mtype: 1,
        cert: Buffer.alloc(32, 0xAB) // Wrong hash
    }];

    let logMessages = [];
    const verifier = dane.createDaneVerifier(tlsaRecords, {
        verify: true,
        logger: entry => logMessages.push(entry)
    });

    const result = verifier('mail.example.com', rawPeerCert);
    test.ok(result instanceof Error, 'Should return an Error for non-matching TLSA');
    test.equal(result.code, 'DANE_VERIFICATION_FAILED', 'Error code should be DANE_VERIFICATION_FAILED');
    test.ok(result.message.includes('mail.example.com'), 'Error should include hostname');

    const failLog = logMessages.find(l => l.msg === 'DANE verification failed');
    test.ok(failLog, 'Should log DANE verification failed');
    test.done();
};

/**
 * Test createDaneVerifier with verify:false logs failure but returns undefined
 */
module.exports.createDaneVerifierVerifyFalseLogsButPasses = test => {
    const { publicKey } = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const spkiDer = publicKey.export({ type: 'spki', format: 'der' });

    const rawPeerCert = {
        raw: Buffer.from('fake-cert-der'),
        pubkey: spkiDer
    };

    const tlsaRecords = [{
        usage: 3,
        selector: 1,
        mtype: 1,
        cert: Buffer.alloc(32, 0xAB) // Wrong hash
    }];

    let logMessages = [];
    const verifier = dane.createDaneVerifier(tlsaRecords, {
        verify: false,
        logger: entry => logMessages.push(entry)
    });

    const result = verifier('mail.example.com', rawPeerCert);
    test.equal(result, undefined, 'Should return undefined (pass) when verify is false');

    const failLog = logMessages.find(l => l.msg === 'DANE verification failed');
    test.ok(failLog, 'Should still log DANE verification failed');
    test.done();
};

/**
 * Test createDaneVerifier with X509Certificate-style cert
 */
module.exports.createDaneVerifierE2EX509Certificate = test => {
    const { publicKey } = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const spkiDer = publicKey.export({ type: 'spki', format: 'der' });
    const spkiHash = nodeCrypto.createHash('sha256').update(spkiDer).digest();

    // Simulate X509Certificate (has .publicKey as KeyObject)
    const x509Cert = {
        raw: Buffer.from('fake-cert-der'),
        publicKey
    };

    const tlsaRecords = [{
        usage: 3,
        selector: 1,
        mtype: 1,
        cert: spkiHash
    }];

    const verifier = dane.createDaneVerifier(tlsaRecords, { verify: true, logger: () => {} });
    const result = verifier('mail.example.com', x509Cert);
    test.equal(result, undefined, 'Should return undefined (success) for X509Certificate with matching TLSA');
    test.done();
};

/**
 * Test that multiple TLSA records are tried and first match wins
 */
module.exports.verifyCertMultipleTlsaRecordsFirstMatchWins = test => {
    const { publicKey } = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const spkiDer = publicKey.export({ type: 'spki', format: 'der' });
    const spkiHash = nodeCrypto.createHash('sha256').update(spkiDer).digest();

    const rawPeerCert = {
        raw: Buffer.from('fake-cert-der'),
        pubkey: spkiDer
    };

    const tlsaRecords = [
        {
            usage: 3,
            selector: 1,
            mtype: 1,
            cert: Buffer.alloc(32, 0xAB) // Wrong — won't match
        },
        {
            usage: 3,
            selector: 1,
            mtype: 1,
            cert: spkiHash // Correct — should match
        }
    ];

    const result = dane.verifyCertAgainstTlsa(rawPeerCert, tlsaRecords);
    test.equal(result.valid, true, 'Should match the second TLSA record');
    test.ok(result.matchedRecord.cert.equals(spkiHash), 'Matched record should be the correct one');
    test.done();
};
