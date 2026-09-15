#!/usr/bin/env node

import { isPath, isValidColName, isValidDbName, isValidMongoURL, Validator } from './utils.js';
import { createWriteStream, createReadStream } from "fs";
import { Endpoints, getConfig } from './values.js';
import { ReadableBit } from '@deflexable/bit-stream';
import { createInterface } from "node:readline";
import backup from "./core/backup.js";
import restore from './core/restore.js';
import { stat } from 'node:fs/promises';
import { request } from 'node:http';
import { createHash } from 'node:crypto';

let startTime = Date.now();
const LOCAL_MARKER = {
    description: '@local',
    toString: () => '@local',
    valueOf: () => '@local',
};

const externalConfig = await getConfig();

const { onMongodbOption } = externalConfig || {};

const getArgs = () =>
    Object.fromEntries(
        process.argv
            .slice(2)
            .map(e => {
                const [k, ...v] = e.split('=');
                return [k, v.join('=')];
            })
    );

const {
    storage,
    read: readFrom,
    write: writeTo,
    db_url,
    db_name,
    col
} = { ...externalConfig, ...process.env, ...getArgs() };

const read = readFrom === LOCAL_MARKER.description ? LOCAL_MARKER : readFrom;
const write = writeTo === LOCAL_MARKER.description ? LOCAL_MARKER : writeTo;

let database = externalConfig.database;

if (db_url) {
    let this_url = db_url;

    if (db_url === LOCAL_MARKER.description) {
        this_url = 'mongodb://localhost:27017';
    } else if (!isValidMongoURL(db_url))
        throw `invalid db_url: ${db_url}`;

    if (db_name !== '*' && !isValidDbName(db_name))
        throw `expected '*' or a valid db_name but got: ${db_name}`;

    if (col !== '*' && !isValidColName(col))
        throw `expected '*' or a valid collection name but got: ${col}`;

    database = {
        [this_url]:
            db_name === '*'
                ? '*'
                : ({ [db_name]: col === '*' ? '*' : [col] })
    };
}

const cleanup = () => {
    console.log(`backup read from ${read} and written to ${write}`);
    console.log(`process took ${Date.now() - startTime}ms`);
    process.exit(0);
}

if (Validator.LINK(read) && isPath(write)) {
    // write backup data from a remote server to a file
    const remote_url = new URL(read);
    remote_url.pathname = Endpoints.backup;

    const passkey = await askQuestion('Enter Request Passkey');

    const offset =
        await stat(write)
            .then(r => r.size)
            .catch(() => 0);

    const response =
        await fetch(remote_url, {
            method: 'GET',
            headers:
                sanitizeHeader({
                    passkey,
                    storage,
                    database: JSON.stringify(database),
                    offset
                })
        });

    if (!response.ok) {
        throw await response.text();
    }

    const readable = new ReadableBit();

    const isAppend = response.headers.get('fs-strategy') === 'APPEND';
    const output = createWriteStream(write, isAppend ? { flags: 'a' } : undefined);

    if (isAppend) console.warn('Resuming from last byte:', offset);

    readable.on('data', chunk => {
        const tip = chunk.subarray(0, 1).toString('utf8');
        const message = chunk.subarray(1);

        if (tip === 'H') {
            process.stdout.write(message);
        } else {
            output.write(message);
        }
    });

    readable.on('end', () => {
        output.end();
        cleanup();
    });

    readable.on('error', err => {
        output.destroy(err);
        console.error(err);
        process.exit(1);
    });

    const reader = response.body.getReader();

    while (true) {
        const { done, value } = await reader.read();

        if (done) {
            readable.end();
            break;
        }

        readable.write(value);
    }
} else if (isPath(read) && Validator.LINK(write)) {
    // write a backup data from a file to a remote server
    const passkey = await askQuestion('Enter Request Passkey');

    const file_id =
        await stat(read).then(r => {
            if (!r.isFile()) throw `'${read}' is not of type file`;

            return createHash('sha256')
                .update(`${r.size}-${read}`, 'utf8')
                .digest('base64')
                .substring(0, 30);
        });

    const remote_url = new URL(write);
    remote_url.pathname = Endpoints.restore;

    const req =
        request(remote_url, {
            method: 'POST',
            headers:
                sanitizeHeader({
                    'Transfer-Encoding': 'chunked',
                    passkey,
                    storage,
                    database: JSON.stringify(database),
                    file_id,
                    'Expect': '100-continue'
                })
        });

    let isOk;

    req.on('information', info => {
        let start = info?.headers['fs-start'];

        if (start) {
            start = (start * 1) || 0;
            console.log('Resuming write from last byte:', start);
            const readable = createReadStream(read, start ? { start } : undefined);
            readable.pipe(req);
            isOk = true;
        }
    });

    req.on('response', (res) => {
        res.on('data', (chunk) => {
            process.stdout.write(chunk);
        });

        res.on('end', () => {
            if (isOk) {
                cleanup();
            } else process.exit(1);
        });

        res.on('error', (err) => {
            console.error(err);
            process.exit(1);
        });
    });

    req.on('error', (err) => {
        console.error(err);
        process.exit(1);
    });

    req.flushHeaders();
} else if (read === LOCAL_MARKER && isPath(write)) {
    // download backup data from local to a file
    const password = await askQuestion('Enter Encryption Password (optional)');
    let databaseMap;

    const stream =
        backup({
            password: password || undefined,
            storage,
            onMongodbOption,
            database,
            onProgress: s => {
                databaseMap = s.database;
                logLine(`extracted ${s.documents} documents & ${s.files} files`);
            }
        });

    stream.on('end', () => {
        if (databaseMap)
            process.stdout.write(`\n${JSON.stringify(databaseMap, null, 2)}\n`);
        cleanup();
    });

    stream.on('error', err => {
        console.error(err);
        process.exit(1);
    });

    stream.pipe(createWriteStream(write));
} else if (isPath(read) && write === LOCAL_MARKER) {
    // restore backup data from a file to local
    const password = await askQuestion('Enter Decryption Password (optional)');

    const stream = createReadStream(read);

    stream.pipe(
        restore({
            password: password || undefined,
            storage,
            onMongodbOption,
            onProgress: s => {
                logLine(`restored ${s.documents} documents & ${s.files} files`);
            },
            onComplete: (r) => {
                process.stdout.write(`\n${JSON.stringify(r, null, 2)}\n`);
                cleanup();
            },
            onError: err => {
                console.error(err);
                process.exit(1);
            }
        })
    );
} else if (Validator.LINK(read) && Validator.LINK(write)) {
    // transfer data between two servers
    const passkey = await askQuestion('Enter Request Passkey');

    const remote_url = new URL(write);
    remote_url.pathname = Endpoints.transfer;

    const response =
        await fetch(remote_url, {
            headers:
                sanitizeHeader({
                    passkey,
                    storage,
                    database: JSON.stringify(database),
                    read
                })
        });

    if (!response.ok) {
        throw await response.text();
    }

    res.on('data', (chunk) => {
        process.stdout.write(chunk);
    });

    res.on('end', cleanup);

    res.on('error', (err) => {
        console.error(err);
        process.exit(1);
    });
} else if (read === LOCAL_MARKER && write === LOCAL_MARKER) {
    console.log(`illegal operation: cannot read from ${read} and write to ${write}`);
    process.exit(1);
} else {
    console.error(`read and write is missing or invalid, must be either a valid http(s) link, a file path or '${LOCAL_MARKER.description}' but instead got read: ${read} and write: ${write}`);
    process.exit(1);
}

function askQuestion(question) {
    return new Promise(resolve => {
        const rl = createInterface({
            input: process.stdin,
            output: process.stdout
        });

        rl.question(`${question}: `, (value) => {
            startTime = Date.now();
            resolve(value);
            rl.close();
        });
    });
}

function logLine(text) {
    process.stdout.write(`\r\x1b[K${text}`);
}

function sanitizeHeader(o) {
    return Object.fromEntries(
        Object.entries(o).filter(v => ![undefined, null, NaN].includes(v[1]))
    );
}