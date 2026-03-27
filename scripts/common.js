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

// --- HTTP/1.1 parsing from raw SSL bytes ---

var _HTTP_METHODS = ["GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD ", "OPTIONS "];
var _HTTP_RESPONSE_PREFIX = "HTTP/";

function rawBytesToString(buf, off, len, maxLen) {
    // Convert raw Java byte array to string preserving ASCII, replacing non-printable with dots
    maxLen = maxLen || 8192;
    var end = Math.min(len, maxLen);
    var output = "";
    for (var i = 0; i < end; i++) {
        var b = buf[off + i] & 0xFF;
        if (b === 0x0D) output += "\r";
        else if (b === 0x0A) output += "\n";
        else if (b >= 32 && b <= 126) output += String.fromCharCode(b);
        else output += ".";
    }
    return output;
}

function isHttpRequest(buf, off, len) {
    // Check if the raw bytes start with an HTTP method
    if (len < 4) return false;
    var first4 = "";
    for (var i = 0; i < Math.min(len, 8); i++) {
        var b = buf[off + i] & 0xFF;
        if (b >= 32 && b <= 126) first4 += String.fromCharCode(b);
        else break;
    }
    for (var j = 0; j < _HTTP_METHODS.length; j++) {
        if (first4.indexOf(_HTTP_METHODS[j]) === 0) return true;
    }
    return false;
}

function isHttpResponse(buf, off, len) {
    // Check if the raw bytes start with "HTTP/"
    if (len < 5) return false;
    var first5 = "";
    for (var i = 0; i < 5; i++) {
        var b = buf[off + i] & 0xFF;
        first5 += String.fromCharCode(b);
    }
    return first5 === _HTTP_RESPONSE_PREFIX;
}

function parseHttpRequest(str) {
    // Parse an HTTP/1.1 request from a string
    // Returns {method, path, version, headers, body_preview, host} or null
    try {
        var headerEnd = str.indexOf("\r\n\r\n");
        var headerPart = headerEnd >= 0 ? str.substring(0, headerEnd) : str;
        var bodyPart = headerEnd >= 0 ? str.substring(headerEnd + 4) : "";

        var lines = headerPart.split("\r\n");
        if (lines.length < 1) return null;

        // Parse request line: "GET /path HTTP/1.1"
        var reqLine = lines[0];
        var spaceIdx = reqLine.indexOf(" ");
        if (spaceIdx < 0) return null;
        var method = reqLine.substring(0, spaceIdx);
        var rest = reqLine.substring(spaceIdx + 1);
        var spaceIdx2 = rest.lastIndexOf(" ");
        var path = spaceIdx2 >= 0 ? rest.substring(0, spaceIdx2) : rest;
        var version = spaceIdx2 >= 0 ? rest.substring(spaceIdx2 + 1) : "";

        // Validate method
        var validMethod = false;
        for (var i = 0; i < _HTTP_METHODS.length; i++) {
            if (method + " " === _HTTP_METHODS[i]) { validMethod = true; break; }
        }
        if (!validMethod) return null;

        // Parse headers
        var headers = {};
        var host = "";
        for (var j = 1; j < lines.length; j++) {
            var colonIdx = lines[j].indexOf(":");
            if (colonIdx > 0) {
                var key = lines[j].substring(0, colonIdx).trim();
                var val = lines[j].substring(colonIdx + 1).trim();
                headers[key] = val;
                if (key.toLowerCase() === "host") host = val;
            }
        }

        return {
            method: method,
            path: path,
            version: version,
            headers: headers,
            host: host,
            body_preview: bodyPart ? bodyPart.substring(0, 4096) : "",
            body_length: bodyPart.length
        };
    } catch(e) {
        return null;
    }
}

function parseHttpResponse(str) {
    // Parse an HTTP/1.1 response from a string
    // Returns {version, status, reason, headers, body_preview} or null
    try {
        var headerEnd = str.indexOf("\r\n\r\n");
        var headerPart = headerEnd >= 0 ? str.substring(0, headerEnd) : str;
        var bodyPart = headerEnd >= 0 ? str.substring(headerEnd + 4) : "";

        var lines = headerPart.split("\r\n");
        if (lines.length < 1) return null;

        // Parse status line: "HTTP/1.1 200 OK"
        var statusLine = lines[0];
        var spaceIdx = statusLine.indexOf(" ");
        if (spaceIdx < 0) return null;
        var version = statusLine.substring(0, spaceIdx);
        var rest = statusLine.substring(spaceIdx + 1);
        var spaceIdx2 = rest.indexOf(" ");
        var statusStr = spaceIdx2 >= 0 ? rest.substring(0, spaceIdx2) : rest;
        var reason = spaceIdx2 >= 0 ? rest.substring(spaceIdx2 + 1) : "";
        var status = parseInt(statusStr, 10);
        if (isNaN(status) || status < 100 || status > 999) return null;

        // Parse headers
        var headers = {};
        for (var j = 1; j < lines.length; j++) {
            var colonIdx = lines[j].indexOf(":");
            if (colonIdx > 0) {
                var key = lines[j].substring(0, colonIdx).trim();
                var val = lines[j].substring(colonIdx + 1).trim();
                headers[key] = val;
            }
        }

        return {
            version: version,
            status: status,
            reason: reason,
            headers: headers,
            body_preview: bodyPart ? bodyPart.substring(0, 4096) : "",
            body_length: bodyPart.length
        };
    } catch(e) {
        return null;
    }
}

function guessBodyFormat(s) {
    if (!s || s.length === 0) return "empty";
    var c = s.charAt(0);
    if (c === '{' || c === '[') return "json";
    if (s.indexOf("<?xml") === 0) return "xml";
    if (s.indexOf("--") === 0) return "multipart";
    return "text";
}

// Extract headers from com.android.okhttp.Headers or okhttp3.Headers
function extractHeaders(headers) {
    var obj = {};
    try {
        var count = headers.size();
        for (var i = 0; i < count; i++) {
            obj[headers.name(i)] = headers.value(i);
        }
    } catch(e) {}
    return obj;
}
