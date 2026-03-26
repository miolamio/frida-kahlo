// scripts/common.js
// Shared utilities for all Frida-Kahlo scripts

function sendEvent(module, type, data) {
    send(JSON.stringify({
        ts: new Date().toISOString(),
        module: module,
        type: type,
        data: data
    }));
}

function safeHook(className, callback) {
    try {
        var clazz = Java.use(className);
        callback(clazz);
        return true;
    } catch (e) {
        return false;
    }
}

function stackTrace() {
    try {
        return Java.use("android.util.Log")
            .getStackTraceString(Java.use("java.lang.Exception").$new())
            .substring(0, 500);
    } catch (e) {
        return "";
    }
}

function readableBytes(buf, off, len, maxLen) {
    maxLen = maxLen || 4096;
    var output = "";
    var end = Math.min(len, maxLen);
    for (var i = 0; i < end; i++) {
        var b = buf[off + i] & 0xFF;
        output += (b >= 32 && b <= 126) ? String.fromCharCode(b) : ".";
    }
    return output;
}

function detectFormat(bytes, len) {
    if (len < 1) return "empty";
    var first = bytes[0] & 0xFF;
    if (first === 0x7B || first === 0x5B) return "json";         // { or [
    if (first === 0x08 || first === 0x0A) return "protobuf";     // common tags
    if (first >= 0x80 && first <= 0x8F) return "msgpack_map";
    if (first >= 0x90 && first <= 0x9F) return "msgpack_array";
    if (first === 0x1F && len > 1 && (bytes[1] & 0xFF) === 0x8B) return "gzip";
    return "binary";
}
