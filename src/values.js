import { resolve as resolveAsPath } from 'path';

export const Endpoints = {
    backup: '/backup',
    restore: '/restore',
    transfer: '/transfer'
};

export const BLOCKS_IDENTIFIERS = {
    DB_URL: '==>[DB_URL]:',
    DB_NAME: '==>[DB_NAME]:',
    COLLECTION: '==>[COL]:',
    DOCUMENT: '==>[DOC]:',
    STORAGE_DIRECTORY: '==>[DIR]:',
    STORAGE_FILE_PATH: '==>[FILE_PATH]:',
    STORAGE_FILE: '==>[FILE]:'
};

export const OTP_CONFIG_FILE = 'mosquito.config.js';

export const getConfig = () =>
    import(resolveAsPath(process.cwd(), './mosquito.config.js'))
        .catch(() => ({}));