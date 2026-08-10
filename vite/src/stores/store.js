import { validatenull } from '@/util/validate';

const keyName = "chrelyonly-";

/**
 * 存储 localStorage / sessionStorage
 */
export const setStore = (params = {}) => {
    let { name, content, type } = params;
    name = keyName + name;
    let obj = {
        dataType: typeof (content),
        content: content,
        type: type,
        datetime: new Date().getTime()
    };
    if (type) {
        window.sessionStorage.setItem(name, JSON.stringify(obj));
    } else {
        window.localStorage.setItem(name, JSON.stringify(obj));
    }
};

/**
 * 获取 localStorage / sessionStorage
 */
export const getStore = (params = {}) => {
    let { name, debug } = params;
    name = keyName + name;
    let obj = {};
    let content;

    obj = window.sessionStorage.getItem(name);
    if (validatenull(obj)) {
        obj = window.localStorage.getItem(name);
    }
    if (validatenull(obj)) {
        return null;
    }

    try {
        obj = JSON.parse(obj);
    } catch {
        return obj;
    }

    if (debug) {
        return obj;
    }

    if (obj.dataType === 'string') {
        content = obj.content;
    } else if (obj.dataType === 'number') {
        content = Number(obj.content);
    } else if (obj.dataType === 'boolean') {
        content = String(obj.content) === 'true';
    } else if (obj.dataType === 'object') {
        content = obj.content;
    }
    return content;
};

/**
 * 删除 localStorage / sessionStorage
 */
export const removeStore = (params = {}) => {
    let { name, type } = params;
    name = keyName + name;
    if (type) {
        window.sessionStorage.removeItem(name);
    } else {
        window.localStorage.removeItem(name);
    }
};

/**
 * 获取全部 localStorage / sessionStorage
 */
export const getAllStore = (params = {}) => {
    let list = [];
    let { type } = params;
    const storage = type ? window.sessionStorage : window.localStorage;

    for (let i = 0; i < storage.length; i++) {
        let rawKey = storage.key(i);
        if (rawKey && rawKey.startsWith(keyName)) {
            // 剥离 keyName 避免 getStore 重复叠加 keyName
            let cleanKey = rawKey.replace(keyName, '');
            list.push({
                name: cleanKey,
                content: getStore({ name: cleanKey })
            });
        }
    }
    return list;
};

/**
 * 清空全部 localStorage / sessionStorage
 */
export const clearStore = (params = {}) => {
    let { name, type } = params;
    if (name) {
        removeStore({ name, type });
    } else {
        if (type) {
            window.sessionStorage.clear();
        } else {
            window.localStorage.clear();
        }
    }
};