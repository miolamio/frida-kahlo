// scripts/hooks/vault.js
// Frida-Kahlo Vault Hook — captures storage & secrets operations
// SharedPreferences, SQLite, File I/O, KeyStore

(function() {
    "use strict";

    var MAX_VALUE_LEN = 2048;

    function truncValue(v) {
        if (v === null || v === undefined) return null;
        var s = v.toString();
        if (s.length > MAX_VALUE_LEN) return s.substring(0, MAX_VALUE_LEN) + "...";
        return s;
    }

    // === SharedPreferences hooks ===
    try {
        Java.perform(function() {
            // Hook SharedPreferences read operations
            safeHook("android.app.SharedPreferencesImpl", function(cls) {
                // getString
                try {
                    cls.getString.implementation = function(key, defValue) {
                        var result = this.getString.call(this, key, defValue);
                        try {
                            var file = this.mFile.value ? this.mFile.value.getName() : "unknown";
                            sendEvent("vault", "pref_read", {
                                file: file,
                                key: key,
                                value: truncValue(result),
                                value_type: "string"
                            });
                        } catch(e) {}
                        return result;
                    };
                } catch(e) {}

                // getInt
                try {
                    cls.getInt.implementation = function(key, defValue) {
                        var result = this.getInt.call(this, key, defValue);
                        try {
                            var file = this.mFile.value ? this.mFile.value.getName() : "unknown";
                            sendEvent("vault", "pref_read", {
                                file: file,
                                key: key,
                                value: result,
                                value_type: "int"
                            });
                        } catch(e) {}
                        return result;
                    };
                } catch(e) {}

                // getBoolean
                try {
                    cls.getBoolean.implementation = function(key, defValue) {
                        var result = this.getBoolean.call(this, key, defValue);
                        try {
                            var file = this.mFile.value ? this.mFile.value.getName() : "unknown";
                            sendEvent("vault", "pref_read", {
                                file: file,
                                key: key,
                                value: result,
                                value_type: "boolean"
                            });
                        } catch(e) {}
                        return result;
                    };
                } catch(e) {}

                // getLong
                try {
                    cls.getLong.implementation = function(key, defValue) {
                        var result = this.getLong.call(this, key, defValue);
                        try {
                            var file = this.mFile.value ? this.mFile.value.getName() : "unknown";
                            sendEvent("vault", "pref_read", {
                                file: file,
                                key: key,
                                value: result,
                                value_type: "long"
                            });
                        } catch(e) {}
                        return result;
                    };
                } catch(e) {}

                // getFloat
                try {
                    cls.getFloat.implementation = function(key, defValue) {
                        var result = this.getFloat.call(this, key, defValue);
                        try {
                            var file = this.mFile.value ? this.mFile.value.getName() : "unknown";
                            sendEvent("vault", "pref_read", {
                                file: file,
                                key: key,
                                value: result,
                                value_type: "float"
                            });
                        } catch(e) {}
                        return result;
                    };
                } catch(e) {}
            });

            // Hook SharedPreferences.Editor write operations
            safeHook("android.app.SharedPreferencesImpl$EditorImpl", function(cls) {
                // putString
                try {
                    cls.putString.implementation = function(key, value) {
                        sendEvent("vault", "pref_write", {
                            key: key,
                            value: truncValue(value),
                            value_type: "string"
                        });
                        return this.putString(key, value);
                    };
                } catch(e) {}

                // putInt
                try {
                    cls.putInt.implementation = function(key, value) {
                        sendEvent("vault", "pref_write", {
                            key: key,
                            value: value,
                            value_type: "int"
                        });
                        return this.putInt(key, value);
                    };
                } catch(e) {}

                // putBoolean
                try {
                    cls.putBoolean.implementation = function(key, value) {
                        sendEvent("vault", "pref_write", {
                            key: key,
                            value: value,
                            value_type: "boolean"
                        });
                        return this.putBoolean(key, value);
                    };
                } catch(e) {}

                // putLong
                try {
                    cls.putLong.implementation = function(key, value) {
                        sendEvent("vault", "pref_write", {
                            key: key,
                            value: value,
                            value_type: "long"
                        });
                        return this.putLong(key, value);
                    };
                } catch(e) {}

                // putFloat
                try {
                    cls.putFloat.implementation = function(key, value) {
                        sendEvent("vault", "pref_write", {
                            key: key,
                            value: value,
                            value_type: "float"
                        });
                        return this.putFloat(key, value);
                    };
                } catch(e) {}
            });
        });
    } catch(e) {}

    // === SQLite hooks ===
    try {
        Java.perform(function() {
            safeHook("android.database.sqlite.SQLiteDatabase", function(cls) {
                // rawQuery
                try {
                    cls.rawQuery.overload('java.lang.String', '[Ljava.lang.String;').implementation = function(sql, args) {
                        var result = this.rawQuery(sql, args);
                        try {
                            var db = this.getPath();
                            var argsStr = args ? Java.use("java.util.Arrays").toString(args) : "[]";
                            sendEvent("vault", "sqlite_query", {
                                db: db,
                                sql: truncValue(sql),
                                args: argsStr,
                                type: "rawQuery"
                            });
                        } catch(e) {}
                        return result;
                    };
                } catch(e) {}

                // insert
                try {
                    cls.insert.implementation = function(table, nullColumnHack, values) {
                        try {
                            var db = this.getPath();
                            sendEvent("vault", "sqlite_write", {
                                db: db,
                                table: table,
                                values: values ? truncValue(values.toString()) : "",
                                type: "insert"
                            });
                        } catch(e) {}
                        return this.insert(table, nullColumnHack, values);
                    };
                } catch(e) {}

                // update
                try {
                    cls.update.overload('java.lang.String', 'android.content.ContentValues', 'java.lang.String', '[Ljava.lang.String;').implementation = function(table, values, where, whereArgs) {
                        try {
                            var db = this.getPath();
                            sendEvent("vault", "sqlite_write", {
                                db: db,
                                table: table,
                                values: values ? truncValue(values.toString()) : "",
                                where: where || "",
                                type: "update"
                            });
                        } catch(e) {}
                        return this.update(table, values, where, whereArgs);
                    };
                } catch(e) {}

                // execSQL
                try {
                    cls.execSQL.overload('java.lang.String').implementation = function(sql) {
                        try {
                            var db = this.getPath();
                            sendEvent("vault", "sqlite_exec", {
                                db: db,
                                sql: truncValue(sql),
                                type: "execSQL"
                            });
                        } catch(e) {}
                        return this.execSQL(sql);
                    };
                } catch(e) {}
            });
        });
    } catch(e) {}

    // === File I/O hooks (internal storage only) ===
    try {
        Java.perform(function() {
            safeHook("java.io.FileOutputStream", function(cls) {
                try {
                    cls.write.overload('[B', 'int', 'int').implementation = function(buf, off, len) {
                        try {
                            var fd = this.getFD();
                            // Try to get path
                            var path = "";
                            try {
                                path = this.path.value || "";
                            } catch(e) {
                                try {
                                    // Alternative: get from fd
                                    path = fd.toString();
                                } catch(e2) {}
                            }
                            if (path && path.indexOf("/data/") !== -1) {
                                sendEvent("vault", "file_write", {
                                    path: path,
                                    size: len,
                                    preview: readableBytes(buf, off, len, 256)
                                });
                            }
                        } catch(e) {}
                        return this.write(buf, off, len);
                    };
                } catch(e) {}
            });
        });
    } catch(e) {}

    // === KeyStore hooks ===
    try {
        Java.perform(function() {
            safeHook("java.security.KeyStore", function(cls) {
                // getKey
                try {
                    cls.getKey.implementation = function(alias, password) {
                        var result = this.getKey(alias, password);
                        sendEvent("vault", "keystore_read", {
                            alias: alias,
                            type: result ? result.getAlgorithm() : "null",
                            op: "getKey"
                        });
                        return result;
                    };
                } catch(e) {}

                // getEntry
                try {
                    cls.getEntry.implementation = function(alias, protParam) {
                        var result = this.getEntry(alias, protParam);
                        sendEvent("vault", "keystore_read", {
                            alias: alias,
                            type: result ? result.getClass().getName() : "null",
                            op: "getEntry"
                        });
                        return result;
                    };
                } catch(e) {}

                // aliases
                try {
                    cls.aliases.implementation = function() {
                        var result = this.aliases();
                        try {
                            var aliasList = [];
                            var enumCopy = this.aliases.call(this);
                            while (enumCopy.hasMoreElements()) {
                                aliasList.push(enumCopy.nextElement().toString());
                            }
                            if (aliasList.length > 0) {
                                sendEvent("vault", "keystore_enum", {
                                    aliases: aliasList,
                                    count: aliasList.length
                                });
                            }
                        } catch(e) {}
                        return result;
                    };
                } catch(e) {}
            });
        });
    } catch(e) {}

    // === Initial dump (delayed to let app initialize) ===
    setTimeout(function() {
        try {
            Java.perform(function() {
                var dump = { prefs: {}, databases: [] };

                try {
                    var ActivityThread = Java.use("android.app.ActivityThread");
                    var ctx = ActivityThread.currentApplication().getApplicationContext();

                    // Dump SharedPreferences
                    try {
                        var prefsDir = Java.use("java.io.File").$new(
                            ctx.getApplicationInfo().dataDir.value + "/shared_prefs"
                        );
                        if (prefsDir.exists()) {
                            var files = prefsDir.listFiles();
                            if (files) {
                                for (var i = 0; i < files.length; i++) {
                                    var fname = files[i].getName().replace(".xml", "");
                                    try {
                                        var prefs = ctx.getSharedPreferences(fname, 0);
                                        var all = prefs.getAll();
                                        var map = {};
                                        var keys = all.keySet().iterator();
                                        var count = 0;
                                        while (keys.hasNext() && count < 100) {
                                            var key = keys.next().toString();
                                            var val = all.get(key);
                                            map[key] = val !== null ? truncValue(val.toString()) : null;
                                            count++;
                                        }
                                        dump.prefs[fname] = map;
                                    } catch(e) {}
                                }
                            }
                        }
                    } catch(e) {}

                    // List databases
                    try {
                        var dbList = ctx.databaseList();
                        if (dbList) {
                            for (var j = 0; j < dbList.length; j++) {
                                dump.databases.push(dbList[j]);
                            }
                        }
                    } catch(e) {}

                } catch(e) {}

                sendEvent("vault", "initial_dump", dump);
            });
        } catch(e) {}
    }, 5000);

    sendEvent("vault", "hook_status", {status: "loaded"});
})();
