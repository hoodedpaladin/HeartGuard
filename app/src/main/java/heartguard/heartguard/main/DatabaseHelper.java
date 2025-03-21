package heartguard.heartguard.main;

/*
    This file is part of NetGuard.

    NetGuard is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    NetGuard is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with NetGuard.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2015-2019 by Marcel Bokhorst (M66B)
*/

import android.content.ContentValues;
import android.content.Context;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteDoneException;
import android.database.sqlite.SQLiteOpenHelper;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Message;
import android.util.Log;

import androidx.preference.PreferenceManager;

import java.io.File;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class DatabaseHelper extends SQLiteOpenHelper {
    private static final String TAG = "NetGuard.Database";

    private static final String DB_NAME = "Netguard";
    // HeartGuard change - version 22 adds rules table
    private static final int DB_VERSION = 25;

    private static boolean once = true;
    private static List<LogChangedListener> logChangedListeners = new ArrayList<>();
    private static List<AccessChangedListener> accessChangedListeners = new ArrayList<>();
    private static List<ForwardChangedListener> forwardChangedListeners = new ArrayList<>();
    // HeartGuard change - notify of whitelist changes
    private static List<WhitelistChangedListener> whitelistChangedListeners = new ArrayList<>();
    private static List<RuleChangedListener> ruleChangedListeners = new ArrayList<>();

    private static HandlerThread hthread = null;
    private static Handler handler = null;

    private static final Map<Integer, Long> mapUidHosts = new HashMap<>();

    private final static int MSG_LOG = 1;
    private final static int MSG_ACCESS = 2;
    private final static int MSG_FORWARD = 3;
    // HeartGuard change - notify of whitelist changes
    private final static int MSG_WHITELIST = 4;
    // HeartGuard change - notify of rule changes
    private final static int MSG_RULE = 5;

    private SharedPreferences prefs;
    private ReentrantReadWriteLock lock = new ReentrantReadWriteLock(true);

    static {
        hthread = new HandlerThread("DatabaseHelper");
        hthread.start();
        handler = new Handler(hthread.getLooper()) {
            @Override
            public void handleMessage(Message msg) {
                handleChangedNotification(msg);
            }
        };
    }

    private static DatabaseHelper dh = null;

    public static DatabaseHelper getInstance(Context context) {
        if (dh == null)
            dh = new DatabaseHelper(context.getApplicationContext());
        return dh;
    }

    public static void clearCache() {
        synchronized (mapUidHosts) {
            mapUidHosts.clear();
        }
    }

    @Override
    public void close() {
        Log.w(TAG, "Database is being closed");
    }

    private DatabaseHelper(Context context) {
        super(context, DB_NAME, null, DB_VERSION);
        prefs = PreferenceManager.getDefaultSharedPreferences(context);

        if (!once) {
            once = true;

            File dbfile = context.getDatabasePath(DB_NAME);
            if (dbfile.exists()) {
                Log.w(TAG, "Deleting " + dbfile);
                dbfile.delete();
            }

            File dbjournal = context.getDatabasePath(DB_NAME + "-journal");
            if (dbjournal.exists()) {
                Log.w(TAG, "Deleting " + dbjournal);
                dbjournal.delete();
            }
        }
    }

    @Override
    public void onCreate(SQLiteDatabase db) {
        Log.i(TAG, "Creating database " + DB_NAME + " version " + DB_VERSION);
        createTableLog(db);
        createTableAccess(db);
        createTableDns(db);
        createTableForward(db);
        createTableApp(db);
        // HeartGuard change - add rules table
        createTableRules(db);
    }

    @Override
    public void onConfigure(SQLiteDatabase db) {
        db.enableWriteAheadLogging();
        super.onConfigure(db);
    }

    private void createTableLog(SQLiteDatabase db) {
        Log.i(TAG, "Creating log table");
        db.execSQL("CREATE TABLE log (" +
                " ID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL" +
                ", time INTEGER NOT NULL" +
                ", version INTEGER" +
                ", protocol INTEGER" +
                ", flags TEXT" +
                ", saddr TEXT" +
                ", sport INTEGER" +
                ", daddr TEXT" +
                ", dport INTEGER" +
                ", dname TEXT" +
                ", uid INTEGER" +
                ", data TEXT" +
                ", allowed INTEGER" +
                ", connection INTEGER" +
                ", interactive INTEGER" +
                ");");
        db.execSQL("CREATE INDEX idx_log_time ON log(time)");
        db.execSQL("CREATE INDEX idx_log_dest ON log(daddr)");
        db.execSQL("CREATE INDEX idx_log_dname ON log(dname)");
        db.execSQL("CREATE INDEX idx_log_dport ON log(dport)");
        db.execSQL("CREATE INDEX idx_log_uid ON log(uid)");
    }

    private void createTableAccess(SQLiteDatabase db) {
        Log.i(TAG, "Creating access table");
        db.execSQL("CREATE TABLE access (" +
                " ID INTEGER PRIMARY KEY AUTOINCREMENT" +
                ", uid INTEGER NOT NULL" +
                ", version INTEGER NOT NULL" +
                ", protocol INTEGER NOT NULL" +
                ", daddr TEXT NOT NULL" +
                ", dport INTEGER NOT NULL" +
                ", time INTEGER NOT NULL" +
                ", allowed INTEGER" +
                ", block INTEGER NOT NULL" +
                ", sent INTEGER" +
                ", received INTEGER" +
                ", connections INTEGER" +
                ", ruletext TEXT" +
                ", input_daddr TEXT" +
                ", relevant_daddr TEXT" +
                ", comment TEXT" +
                ", pending_allow INTEGER NOT NULL" +
                ");");
        db.execSQL("CREATE UNIQUE INDEX idx_access ON access(uid, version, protocol, daddr, dport)");
        db.execSQL("CREATE INDEX idx_access_daddr ON access(daddr)");
        db.execSQL("CREATE INDEX idx_access_block ON access(block)");
    }

    // HeartGuard change - make a table to hold rules
    private void createTableRules(SQLiteDatabase db) {
        Log.i(TAG, "Creating rules table");
        db.execSQL("CREATE TABLE rules (" +
                " _id INTEGER PRIMARY KEY AUTOINCREMENT" +
                ", ruletext TEXT NOT NULL" +
                ", create_time INTEGER NOT NULL" +
                ", enact_time INTEGER NOT NULL" +
                ", enacted INTEGER NOT NULL" +
                ", major_category INTEGER NOT NULL" +
                ", minor_category INTEGER NOT NULL" +
                ");");
    }

    private void createTableDns(SQLiteDatabase db) {
        Log.i(TAG, "Creating dns table");
        db.execSQL("CREATE TABLE dns (" +
                " ID INTEGER PRIMARY KEY AUTOINCREMENT" +
                ", time INTEGER NOT NULL" +
                ", qname TEXT NOT NULL" +
                ", aname TEXT NOT NULL" +
                ", resource TEXT NOT NULL" +
                ", ttl INTEGER" +
                ");");
        db.execSQL("CREATE UNIQUE INDEX idx_dns ON dns(qname, aname, resource)");
        db.execSQL("CREATE INDEX idx_dns_resource ON dns(resource)");
    }

    private void createTableForward(SQLiteDatabase db) {
        Log.i(TAG, "Creating forward table");
        db.execSQL("CREATE TABLE forward (" +
                " ID INTEGER PRIMARY KEY AUTOINCREMENT" +
                ", protocol INTEGER NOT NULL" +
                ", dport INTEGER NOT NULL" +
                ", raddr TEXT NOT NULL" +
                ", rport INTEGER NOT NULL" +
                ", ruid INTEGER NOT NULL" +
                ");");
        db.execSQL("CREATE UNIQUE INDEX idx_forward ON forward(protocol, dport)");
    }

    private void createTableApp(SQLiteDatabase db) {
        Log.i(TAG, "Creating app table");
        db.execSQL("CREATE TABLE app (" +
                " ID INTEGER PRIMARY KEY AUTOINCREMENT" +
                ", package TEXT" +
                ", label TEXT" +
                ", system INTEGER  NOT NULL" +
                ", internet INTEGER NOT NULL" +
                ", enabled INTEGER NOT NULL" +
                ");");
        db.execSQL("CREATE UNIQUE INDEX idx_package ON app(package)");
    }

    private boolean columnExists(SQLiteDatabase db, String table, String column) {
        Cursor cursor = null;
        try {
            cursor = db.rawQuery("SELECT * FROM " + table + " LIMIT 0", null);
            return (cursor.getColumnIndex(column) >= 0);
        } catch (Throwable ex) {
            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
            return false;
        } finally {
            if (cursor != null)
                cursor.close();
        }
    }

    @Override
    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        Log.i(TAG, DB_NAME + " upgrading from version " + oldVersion + " to " + newVersion);

        db.beginTransaction();
        try {
            if (oldVersion < 2) {
                if (!columnExists(db, "log", "version"))
                    db.execSQL("ALTER TABLE log ADD COLUMN version INTEGER");
                if (!columnExists(db, "log", "protocol"))
                    db.execSQL("ALTER TABLE log ADD COLUMN protocol INTEGER");
                if (!columnExists(db, "log", "uid"))
                    db.execSQL("ALTER TABLE log ADD COLUMN uid INTEGER");
                oldVersion = 2;
            }
            if (oldVersion < 3) {
                if (!columnExists(db, "log", "port"))
                    db.execSQL("ALTER TABLE log ADD COLUMN port INTEGER");
                if (!columnExists(db, "log", "flags"))
                    db.execSQL("ALTER TABLE log ADD COLUMN flags TEXT");
                oldVersion = 3;
            }
            if (oldVersion < 4) {
                if (!columnExists(db, "log", "connection"))
                    db.execSQL("ALTER TABLE log ADD COLUMN connection INTEGER");
                oldVersion = 4;
            }
            if (oldVersion < 5) {
                if (!columnExists(db, "log", "interactive"))
                    db.execSQL("ALTER TABLE log ADD COLUMN interactive INTEGER");
                oldVersion = 5;
            }
            if (oldVersion < 6) {
                if (!columnExists(db, "log", "allowed"))
                    db.execSQL("ALTER TABLE log ADD COLUMN allowed INTEGER");
                oldVersion = 6;
            }
            if (oldVersion < 7) {
                db.execSQL("DROP TABLE log");
                createTableLog(db);
                oldVersion = 8;
            }
            if (oldVersion < 8) {
                if (!columnExists(db, "log", "data"))
                    db.execSQL("ALTER TABLE log ADD COLUMN data TEXT");
                db.execSQL("DROP INDEX idx_log_source");
                db.execSQL("DROP INDEX idx_log_dest");
                db.execSQL("CREATE INDEX idx_log_source ON log(saddr)");
                db.execSQL("CREATE INDEX idx_log_dest ON log(daddr)");
                db.execSQL("CREATE INDEX IF NOT EXISTS idx_log_uid ON log(uid)");
                oldVersion = 8;
            }
            if (oldVersion < 9) {
                createTableAccess(db);
                oldVersion = 9;
            }
            if (oldVersion < 10) {
                db.execSQL("DROP TABLE log");
                db.execSQL("DROP TABLE access");
                createTableLog(db);
                createTableAccess(db);
                oldVersion = 10;
            }
            if (oldVersion < 12) {
                db.execSQL("DROP TABLE access");
                createTableAccess(db);
                oldVersion = 12;
            }
            if (oldVersion < 13) {
                db.execSQL("CREATE INDEX IF NOT EXISTS idx_log_dport ON log(dport)");
                db.execSQL("CREATE INDEX IF NOT EXISTS idx_log_dname ON log(dname)");
                oldVersion = 13;
            }
            if (oldVersion < 14) {
                createTableDns(db);
                oldVersion = 14;
            }
            if (oldVersion < 15) {
                db.execSQL("DROP TABLE access");
                createTableAccess(db);
                oldVersion = 15;
            }
            if (oldVersion < 16) {
                createTableForward(db);
                oldVersion = 16;
            }
            if (oldVersion < 17) {
                if (!columnExists(db, "access", "sent"))
                    db.execSQL("ALTER TABLE access ADD COLUMN sent INTEGER");
                if (!columnExists(db, "access", "received"))
                    db.execSQL("ALTER TABLE access ADD COLUMN received INTEGER");
                oldVersion = 17;
            }
            if (oldVersion < 18) {
                db.execSQL("CREATE INDEX IF NOT EXISTS idx_access_block ON access(block)");
                db.execSQL("DROP INDEX idx_dns");
                db.execSQL("CREATE UNIQUE INDEX IF NOT EXISTS idx_dns ON dns(qname, aname, resource)");
                db.execSQL("CREATE INDEX IF NOT EXISTS idx_dns_resource ON dns(resource)");
                oldVersion = 18;
            }
            if (oldVersion < 19) {
                if (!columnExists(db, "access", "connections"))
                    db.execSQL("ALTER TABLE access ADD COLUMN connections INTEGER");
                oldVersion = 19;
            }
            if (oldVersion < 20) {
                db.execSQL("CREATE INDEX IF NOT EXISTS idx_access_daddr ON access(daddr)");
                oldVersion = 20;
            }
            if (oldVersion < 21) {
                createTableApp(db);
                oldVersion = 21;
            }

            // HeartGuard change - version 22 adds a rules table
            if (oldVersion < 22) {
                db.execSQL("DROP TABLE rules");
                createTableRules(db);
                oldVersion = 22;
            }

            if (oldVersion < 23) {
                db.execSQL("DROP TABLE access");
                createTableAccess(db);
                oldVersion = 23;
            }

            if (oldVersion < 24) {
                db.execSQL("INSERT INTO rules (ruletext,create_time,enact_time,enacted,major_category,minor_category) VALUES (\"allow package:com.google.android.gms\",0, 0, 0, " + MyRule.MAJOR_CATEGORY_ALLOW + ", 0);");
                db.execSQL("INSERT INTO rules (ruletext,create_time,enact_time,enacted,major_category,minor_category) VALUES (\"allow package:com.google.android.gcs\",0, 0, 0, " + MyRule.MAJOR_CATEGORY_ALLOW + ", 0);");
                oldVersion = 24;
            }

            if (oldVersion < 25) {
                db.execSQL("DROP TABLE access");
                createTableAccess(db);
                oldVersion = 25;
            }

            if (oldVersion == DB_VERSION) {
                db.setVersion(oldVersion);
                db.setTransactionSuccessful();
                Log.i(TAG, DB_NAME + " upgraded to " + DB_VERSION);
            } else
                throw new IllegalArgumentException(DB_NAME + " upgraded to " + oldVersion + " but required " + DB_VERSION);

        } catch (Throwable ex) {
            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
        } finally {
            db.endTransaction();
        }
    }

    // Log

    public void insertLog(Packet packet, String dname, int connection, boolean interactive) {
        lock.writeLock().lock();
        try {
            SQLiteDatabase db = this.getWritableDatabase();
            db.beginTransactionNonExclusive();
            try {
                ContentValues cv = new ContentValues();
                cv.put("time", packet.time);
                cv.put("version", packet.version);

                if (packet.protocol < 0)
                    cv.putNull("protocol");
                else
                    cv.put("protocol", packet.protocol);

                cv.put("flags", packet.flags);

                cv.put("saddr", packet.saddr);
                if (packet.sport < 0)
                    cv.putNull("sport");
                else
                    cv.put("sport", packet.sport);

                cv.put("daddr", packet.daddr);
                if (packet.dport < 0)
                    cv.putNull("dport");
                else
                    cv.put("dport", packet.dport);

                if (dname == null)
                    cv.putNull("dname");
                else
                    cv.put("dname", dname);

                cv.put("data", packet.data);

                if (packet.uid < 0)
                    cv.putNull("uid");
                else
                    cv.put("uid", packet.uid);

                cv.put("allowed", packet.allowed ? 1 : 0);

                cv.put("connection", connection);
                cv.put("interactive", interactive ? 1 : 0);

                if (db.insert("log", null, cv) == -1)
                    Log.e(TAG, "Insert log failed");

                db.setTransactionSuccessful();
            } finally {
                db.endTransaction();
            }
        } finally {
            lock.writeLock().unlock();
        }

        notifyLogChanged();
    }

    public void clearLog(int uid) {
        lock.writeLock().lock();
        try {
            SQLiteDatabase db = this.getWritableDatabase();
            db.beginTransactionNonExclusive();
            try {
                if (uid < 0)
                    db.delete("log", null, new String[]{});
                else
                    db.delete("log", "uid = ?", new String[]{Integer.toString(uid)});

                db.setTransactionSuccessful();
            } finally {
                db.endTransaction();
            }

            db.execSQL("VACUUM");
        } finally {
            lock.writeLock().unlock();
        }

        notifyLogChanged();
    }

    public void cleanupLog(long time) {
        lock.writeLock().lock();
        try {
            SQLiteDatabase db = this.getWritableDatabase();
            db.beginTransactionNonExclusive();
            try {
                // There an index on time
                int rows = db.delete("log", "time < ?", new String[]{Long.toString(time)});
                Log.i(TAG, "Cleanup log" +
                        " before=" + SimpleDateFormat.getDateTimeInstance().format(new Date(time)) +
                        " rows=" + rows);

                db.setTransactionSuccessful();
            } finally {
                db.endTransaction();
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    public Cursor getLog(boolean udp, boolean tcp, boolean other, boolean allowed, boolean blocked) {
        lock.readLock().lock();
        try {
            SQLiteDatabase db = this.getReadableDatabase();
            // There is an index on time
            // There is no index on protocol/allowed for write performance
            String query = "SELECT ID AS _id, *";
            query += " FROM log";
            query += " WHERE (0 = 1";
            if (udp)
                query += " OR protocol = 17";
            if (tcp)
                query += " OR protocol = 6";
            if (other)
                query += " OR (protocol <> 6 AND protocol <> 17)";
            query += ") AND (0 = 1";
            if (allowed)
                query += " OR allowed = 1";
            if (blocked)
                query += " OR allowed = 0";
            query += ")";
            query += " ORDER BY time DESC";
            return db.rawQuery(query, new String[]{});
        } finally {
            lock.readLock().unlock();
        }
    }

    public Cursor searchLog(String find) {
        lock.readLock().lock();
        try {
            SQLiteDatabase db = this.getReadableDatabase();
            // There is an index on daddr, dname, dport and uid
            String query = "SELECT ID AS _id, *";
            query += " FROM log";
            query += " WHERE daddr LIKE ? OR dname LIKE ? OR dport = ? OR uid = ?";
            query += " ORDER BY time DESC";
            return db.rawQuery(query, new String[]{"%" + find + "%", "%" + find + "%", find, find});
        } finally {
            lock.readLock().unlock();
        }
    }

    // Access

    public boolean updateAccess(Context context, Packet packet, String dname) {
        int rows;
        // HeartGuard change - notify of whitelist changes
        boolean changed_whitelist = false;

        lock.writeLock().lock();
        try {
            SQLiteDatabase db = this.getWritableDatabase();
            db.beginTransactionNonExclusive();
            try {
                ContentValues cv = new ContentValues();
                cv.put("time", packet.time);
                cv.put("allowed", packet.allowed ? 1 : 0);

                // There is a segmented index on uid, version, protocol, daddr and dport
                rows = db.update("access", cv, "uid = ? AND version = ? AND protocol = ? AND daddr = ? AND dport = ?",
                        new String[]{
                                Integer.toString(packet.uid),
                                Integer.toString(packet.version),
                                Integer.toString(packet.protocol),
                                dname == null ? packet.daddr : dname,
                                Integer.toString(packet.dport)});

                if (rows == 0) {
                    cv.put("uid", packet.uid);
                    cv.put("version", packet.version);
                    cv.put("protocol", packet.protocol);
                    cv.put("daddr", dname == null ? packet.daddr : dname);
                    cv.put("dport", packet.dport);

                    // HeartGuard change - simple whitelist feature
                    WhitelistManager wm = WhitelistManager.getInstance(context);
                    int pending = 0;
                    RuleAllowData result = wm.isPendingAllowed(context, dname == null ? packet.daddr : dname, packet.uid);
                    if (result != null && result.allowed > 0)
                        pending = 1;
                    cv.put("pending_allow", pending);

                    RuleAllowData match = wm.isAllowed(context, packet.daddr, packet.uid);
                    if (match != null && match.allowed == 1)
                    {
                        Log.w(TAG, "Allowing whitelisted domain " + dname + "for UID " + packet.uid);
                        changed_whitelist = true;
                        cv.put("ruletext", match.ruletext);
                        cv.put("input_daddr", match.input_daddr);
                        cv.put("relevant_daddr", match.relevant_daddr);
                        cv.put("block", 0);
                        cv.put("comment", "unblocked in updateAccess");
                    } else {
                        cv.put("block", 1);
                        cv.put("comment", "blocked in updateAccess");
                    }

                    if (db.insert("access", null, cv) == -1)
                        Log.e(TAG, "Insert access failed");
                } else if (rows != 1)
                    Log.e(TAG, "Update access failed rows=" + rows);

                db.setTransactionSuccessful();
            } finally {
                db.endTransaction();
            }
        } finally {
            lock.writeLock().unlock();
        }

        notifyAccessChanged();
        // HeartGuard change - notify of whitelist changes
        if (changed_whitelist) {
            //notifyWhitelistChanged();
            ServiceSinkhole.pleaseUpdateUid(packet.uid, context);
            // Return false, because we allowed it so the user doesn't need to get notified
            return false;
        }
        return (rows == 0);
    }

    public void updateUsage(Usage usage, String dname) {
        lock.writeLock().lock();
        try {
            SQLiteDatabase db = this.getWritableDatabase();
            db.beginTransactionNonExclusive();
            try {
                // There is a segmented index on uid, version, protocol, daddr and dport
                String selection = "uid = ? AND version = ? AND protocol = ? AND daddr = ? AND dport = ?";
                String[] selectionArgs = new String[]{
                        Integer.toString(usage.Uid),
                        Integer.toString(usage.Version),
                        Integer.toString(usage.Protocol),
                        dname == null ? usage.DAddr : dname,
                        Integer.toString(usage.DPort)
                };

                try (Cursor cursor = db.query("access", new String[]{"sent", "received", "connections"}, selection, selectionArgs, null, null, null)) {
                    long sent = 0;
                    long received = 0;
                    int connections = 0;
                    int colSent = cursor.getColumnIndex("sent");
                    int colReceived = cursor.getColumnIndex("received");
                    int colConnections = cursor.getColumnIndex("connections");
                    if (cursor.moveToNext()) {
                        sent = cursor.isNull(colSent) ? 0 : cursor.getLong(colSent);
                        received = cursor.isNull(colReceived) ? 0 : cursor.getLong(colReceived);
                        connections = cursor.isNull(colConnections) ? 0 : cursor.getInt(colConnections);
                    }

                    ContentValues cv = new ContentValues();
                    cv.put("sent", sent + usage.Sent);
                    cv.put("received", received + usage.Received);
                    cv.put("connections", connections + 1);

                    int rows = db.update("access", cv, selection, selectionArgs);
                    if (rows != 1)
                        Log.e(TAG, "Update usage failed rows=" + rows);
                }

                db.setTransactionSuccessful();
            } finally {
                db.endTransaction();
            }
        } finally {
            lock.writeLock().unlock();
        }

        notifyAccessChanged();
    }

    public void setAccess(long id, RuleAllowData ruleAllowData, String comment) {
        lock.writeLock().lock();
        try {
            SQLiteDatabase db = this.getWritableDatabase();
            db.beginTransactionNonExclusive();
            try {
                ContentValues cv = new ContentValues();
                if (ruleAllowData != null && ruleAllowData.allowed == 1) {
                    cv.put("block", 0);
                    cv.put("ruletext", ruleAllowData.ruletext);
                    cv.put("relevant_daddr", ruleAllowData.relevant_daddr);
                    cv.put("input_daddr", ruleAllowData.input_daddr);
                } else {
                    cv.put("block", 1);
                }
                cv.put("allowed", -1);
                cv.put("comment", comment);

                if (db.update("access", cv, "ID = ?", new String[]{Long.toString(id)}) != 1)
                    Log.e(TAG, "Set access failed");

                db.setTransactionSuccessful();
            } finally {
                db.endTransaction();
            }
        } finally {
            lock.writeLock().unlock();
        }

        notifyAccessChanged();
    }

    public void clearAccess() {
        lock.writeLock().lock();
        try {
            SQLiteDatabase db = this.getWritableDatabase();
            db.beginTransactionNonExclusive();
            try {
                db.delete("access", null, null);

                db.setTransactionSuccessful();
            } finally {
                db.endTransaction();
                clearCache();
            }
        } finally {
            lock.writeLock().unlock();
        }

        notifyAccessChanged();
    }

    public void clearAccess(int uid, boolean keeprules) {
        lock.writeLock().lock();
        try {
            SQLiteDatabase db = this.getWritableDatabase();
            db.beginTransactionNonExclusive();
            try {
                // There is a segmented index on uid
                // There is an index on block
                if (keeprules)
                    db.delete("access", "uid = ? AND block < 0", new String[]{Integer.toString(uid)});
                else
                    db.delete("access", "uid = ?", new String[]{Integer.toString(uid)});

                db.setTransactionSuccessful();
            } finally {
                db.endTransaction();
            }
        } finally {
            lock.writeLock().unlock();
        }

        notifyAccessChanged();
    }

    public void resetUsage(int uid) {
        lock.writeLock().lock();
        try {
            // There is a segmented index on uid
            SQLiteDatabase db = this.getWritableDatabase();
            db.beginTransactionNonExclusive();
            try {
                ContentValues cv = new ContentValues();
                cv.putNull("sent");
                cv.putNull("received");
                cv.putNull("connections");
                db.update("access", cv,
                        (uid < 0 ? null : "uid = ?"),
                        (uid < 0 ? null : new String[]{Integer.toString(uid)}));

                db.setTransactionSuccessful();
            } finally {
                db.endTransaction();
            }
        } finally {
            lock.writeLock().unlock();
        }

        notifyAccessChanged();
    }

    public Cursor getAccess(int uid) {
        lock.readLock().lock();
        try {
            SQLiteDatabase db = this.getReadableDatabase();
            // There is a segmented index on uid
            // There is no index on time for write performance
            String query = "SELECT a.ID AS _id, a.*";
            query += ", (SELECT COUNT(DISTINCT d.qname) FROM dns d WHERE d.resource IN (SELECT d1.resource FROM dns d1 WHERE d1.qname = a.daddr)) count";
            query += " FROM access a";
            query += " WHERE a.uid = ?";
            query += " ORDER BY a.time DESC";
            query += " LIMIT 250";
            return db.rawQuery(query, new String[]{Integer.toString(uid)});
        } finally {
            lock.readLock().unlock();
        }
    }

    public Cursor getAccess() {
        lock.readLock().lock();
        try {
            SQLiteDatabase db = this.getReadableDatabase();
            // There is a segmented index on uid
            // There is an index on block
            return db.query("access", null, "block >= 0", null, null, null, "uid");
        } finally {
            lock.readLock().unlock();
        }
    }

    // HeartGuard change - read all access rules
    public Cursor getAllAccess() {
        lock.readLock().lock();
        try {
            SQLiteDatabase db = this.getReadableDatabase();
            // There is a segmented index on uid
            // There is an index on block
            return db.query("access", null, null, null, null, null, null);
        } finally {
            lock.readLock().unlock();
        }
    }

    // HeartGuard change - delete specific Access
    public void clearAccessId(long id) {
        lock.writeLock().lock();
        try {
            SQLiteDatabase db = this.getWritableDatabase();
            db.beginTransactionNonExclusive();
            try {
                // There is a segmented index on uid
                // There is an index on block
                db.delete("access", "ID = ?", new String[]{Long.toString(id)});

                db.setTransactionSuccessful();
            } finally {
                db.endTransaction();
            }
        } finally {
            lock.writeLock().unlock();
        }

        notifyAccessChanged();
    }

    public Cursor getAccessUnset(int uid, int limit, long since) {
        lock.readLock().lock();
        try {
            SQLiteDatabase db = this.getReadableDatabase();
            // There is a segmented index on uid, block and daddr
            // There is no index on allowed and time for write performance
            String query = "SELECT MAX(time) AS time, daddr, allowed";
            query += " FROM access";
            query += " WHERE uid = ?";
            query += " AND block < 0";
            query += " AND time >= ?";
            query += " GROUP BY daddr, allowed";
            query += " ORDER BY time DESC";
            if (limit > 0)
                query += " LIMIT " + limit;
            return db.rawQuery(query, new String[]{Integer.toString(uid), Long.toString(since)});
        } finally {
            lock.readLock().unlock();
        }
    }

    public long getHostCount(int uid, boolean usecache) {
        if (usecache)
            synchronized (mapUidHosts) {
                if (mapUidHosts.containsKey(uid))
                    return mapUidHosts.get(uid);
            }

        lock.readLock().lock();
        try {
            SQLiteDatabase db = this.getReadableDatabase();
            // There is a segmented index on uid
            // There is an index on block
            long hosts = db.compileStatement("SELECT COUNT(*) FROM access WHERE block >= 0 AND uid =" + uid).simpleQueryForLong();
            synchronized (mapUidHosts) {
                mapUidHosts.put(uid, hosts);
            }
            return hosts;
        } finally {
            lock.readLock().unlock();
        }
    }

    // DNS

    public boolean insertDns(ResourceRecord rr) {
        lock.writeLock().lock();
        try {
            SQLiteDatabase db = this.getWritableDatabase();
            db.beginTransactionNonExclusive();
            try {
                int ttl = rr.TTL;

                int min = Integer.parseInt(prefs.getString("ttl", "259200"));
                if (ttl < min)
                    ttl = min;

                ContentValues cv = new ContentValues();
                cv.put("time", rr.Time);
                cv.put("ttl", ttl * 1000L);

                int rows = db.update("dns", cv, "qname = ? AND aname = ? AND resource = ?",
                        new String[]{rr.QName, rr.AName, rr.Resource});

                if (rows == 0) {
                    cv.put("qname", rr.QName);
                    cv.put("aname", rr.AName);
                    cv.put("resource", rr.Resource);

                    if (db.insert("dns", null, cv) == -1)
                        Log.e(TAG, "Insert dns failed");
                    else
                        rows = 1;
                } else if (rows != 1)
                    Log.e(TAG, "Update dns failed rows=" + rows);

                db.setTransactionSuccessful();

                return (rows > 0);
            } finally {
                db.endTransaction();
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    public void cleanupDns() {
        lock.writeLock().lock();
        try {
            SQLiteDatabase db = this.getWritableDatabase();
            db.beginTransactionNonExclusive();
            try {
                // There is no index on time for write performance
                long now = new Date().getTime();
                db.execSQL("DELETE FROM dns WHERE time + ttl < " + now);
                Log.i(TAG, "Cleanup DNS");

                db.setTransactionSuccessful();
            } finally {
                db.endTransaction();
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    public void clearDns() {
        lock.writeLock().lock();
        try {
            SQLiteDatabase db = this.getWritableDatabase();
            db.beginTransactionNonExclusive();
            try {
                db.delete("dns", null, new String[]{});

                db.setTransactionSuccessful();
            } finally {
                db.endTransaction();
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    public String getQName(int uid, String ip) {
        lock.readLock().lock();
        try {
            SQLiteDatabase db = this.getReadableDatabase();
            // There is a segmented index on resource
            String query = "SELECT d.qname";
            query += " FROM dns AS d";
            query += " WHERE d.resource = '" + ip.replace("'", "''") + "'";
            query += " ORDER BY d.qname";
            query += " LIMIT 1";
            // There is no way to known for sure which domain name an app used, so just pick the first one
            return db.compileStatement(query).simpleQueryForString();
        } catch (SQLiteDoneException ignored) {
            // Not found
            return null;
        } finally {
            lock.readLock().unlock();
        }
    }

    public Cursor getAlternateQNames(String qname) {
        lock.readLock().lock();
        try {
            SQLiteDatabase db = this.getReadableDatabase();
            String query = "SELECT DISTINCT d2.qname";
            query += " FROM dns d1";
            query += " JOIN dns d2";
            query += "   ON d2.resource = d1.resource AND d2.id <> d1.id";
            query += " WHERE d1.qname = ?";
            query += " ORDER BY d2.qname";
            return db.rawQuery(query, new String[]{qname});
        } finally {
            lock.readLock().unlock();
        }
    }

    // HeartGuard code - convenience function to get a list of qname and all alternates
    public List<String> getListAlternateQNames(String qname) {
        List<String> alldnames = new LinkedList<>();
        alldnames.add(qname);

        try (Cursor alternates_cursor = dh.getAlternateQNames(qname)) {
            while (alternates_cursor.moveToNext()) {
                alldnames.add(alternates_cursor.getString(0));
            }
        }

        return alldnames;
    }

    // HeartGuard addition to get all QNames in case there is more than one and one of them is allowed
    public Cursor getAllQNames(String ip) {
        lock.readLock().lock();
        try {
            SQLiteDatabase db = this.getReadableDatabase();
            // There is a segmented index on resource
            String query = "SELECT DISTINCT d.qname";
            query += " FROM dns AS d";
            query += " WHERE d.resource = '" + ip.replace("'", "''") + "'";
            query += " ORDER BY d.qname";
            // There is no way to known for sure which domain name an app used, so just pick the first one
            return db.rawQuery(query, new String[]{});
        } finally {
            lock.readLock().unlock();
        }
    }

    public Cursor getDns() {
        lock.readLock().lock();
        try {
            SQLiteDatabase db = this.getReadableDatabase();
            // There is an index on resource
            // There is a segmented index on qname
            String query = "SELECT ID AS _id, *";
            query += " FROM dns";
            query += " ORDER BY resource, qname";
            return db.rawQuery(query, new String[]{});
        } finally {
            lock.readLock().unlock();
        }
    }

    public Cursor getAccessDns(String dname) {
        long now = new Date().getTime();
        lock.readLock().lock();
        try {
            SQLiteDatabase db = this.getReadableDatabase();

            // There is a segmented index on dns.qname
            // There is an index on access.daddr and access.block
            String query = "SELECT a.uid, a.version, a.protocol, a.daddr, d.resource, a.dport, a.block, d.time, d.ttl";
            query += " FROM access AS a";
            query += " LEFT JOIN dns AS d";
            query += "   ON d.qname = a.daddr";
            query += " WHERE a.block >= 0";
            query += " AND (d.time IS NULL OR d.time + d.ttl >= " + now + ")";
            if (dname != null)
                query += " AND a.daddr = ?";

            return db.rawQuery(query, dname == null ? new String[]{} : new String[]{dname});
        } finally {
            lock.readLock().unlock();
        }
    }

    public Cursor getAccessDnsForUid(int uid) {
        long now = new Date().getTime();
        lock.readLock().lock();
        try {
            SQLiteDatabase db = this.getReadableDatabase();

            // There is a segmented index on dns.qname
            // There is an index on access.daddr and access.block
            String query = "SELECT a.uid, a.version, a.protocol, a.daddr, d.resource, a.dport, a.block, d.time, d.ttl";
            query += " FROM access AS a";
            query += " LEFT JOIN dns AS d";
            query += "   ON d.qname = a.daddr";
            query += " WHERE a.block >= 0";
            query += " AND (d.time IS NULL OR d.time + d.ttl >= " + now + ")";
            query += " AND a.uid = " + uid;

            return db.rawQuery(query, new String[]{});
        } finally {
            lock.readLock().unlock();
        }
    }

    // Forward

    public void addForward(int protocol, int dport, String raddr, int rport, int ruid) {
        lock.writeLock().lock();
        try {
            SQLiteDatabase db = this.getWritableDatabase();
            db.beginTransactionNonExclusive();
            try {
                ContentValues cv = new ContentValues();
                cv.put("protocol", protocol);
                cv.put("dport", dport);
                cv.put("raddr", raddr);
                cv.put("rport", rport);
                cv.put("ruid", ruid);

                if (db.insert("forward", null, cv) < 0)
                    Log.e(TAG, "Insert forward failed");

                db.setTransactionSuccessful();
            } finally {
                db.endTransaction();
            }
        } finally {
            lock.writeLock().unlock();
        }

        notifyForwardChanged();
    }

    public void deleteForward() {
        lock.writeLock().lock();
        try {
            SQLiteDatabase db = this.getWritableDatabase();
            db.beginTransactionNonExclusive();
            try {
                db.delete("forward", null, null);

                db.setTransactionSuccessful();
            } finally {
                db.endTransaction();
            }
        } finally {
            lock.writeLock().unlock();
        }

        notifyForwardChanged();
    }

    public void deleteForward(int protocol, int dport) {
        lock.writeLock().lock();
        try {
            SQLiteDatabase db = this.getWritableDatabase();
            db.beginTransactionNonExclusive();
            try {
                db.delete("forward", "protocol = ? AND dport = ?",
                        new String[]{Integer.toString(protocol), Integer.toString(dport)});

                db.setTransactionSuccessful();
            } finally {
                db.endTransaction();
            }
        } finally {
            lock.writeLock().unlock();
        }

        notifyForwardChanged();
    }

    public Cursor getForwarding() {
        lock.readLock().lock();
        try {
            SQLiteDatabase db = this.getReadableDatabase();
            String query = "SELECT ID AS _id, *";
            query += " FROM forward";
            query += " ORDER BY dport";
            return db.rawQuery(query, new String[]{});
        } finally {
            lock.readLock().unlock();
        }
    }

    public void addApp(String packageName, String label, boolean system, boolean internet, boolean enabled) {
        lock.writeLock().lock();
        try {
            SQLiteDatabase db = this.getWritableDatabase();
            db.beginTransactionNonExclusive();
            try {
                ContentValues cv = new ContentValues();
                cv.put("package", packageName);
                if (label == null)
                    cv.putNull("label");
                else
                    cv.put("label", label);
                cv.put("system", system ? 1 : 0);
                cv.put("internet", internet ? 1 : 0);
                cv.put("enabled", enabled ? 1 : 0);

                if (db.insert("app", null, cv) < 0)
                    Log.e(TAG, "Insert app failed");

                db.setTransactionSuccessful();
            } finally {
                db.endTransaction();
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    public Cursor getApp(String packageName) {
        lock.readLock().lock();
        try {
            SQLiteDatabase db = this.getReadableDatabase();

            // There is an index on package
            String query = "SELECT * FROM app WHERE package = ?";

            return db.rawQuery(query, new String[]{packageName});
        } finally {
            lock.readLock().unlock();
        }
    }

    public void clearApps() {
        lock.writeLock().lock();
        try {
            SQLiteDatabase db = this.getWritableDatabase();
            db.beginTransactionNonExclusive();
            try {
                db.delete("app", null, null);
                db.setTransactionSuccessful();
            } finally {
                db.endTransaction();
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    public void addLogChangedListener(LogChangedListener listener) {
        logChangedListeners.add(listener);
    }

    public void removeLogChangedListener(LogChangedListener listener) {
        logChangedListeners.remove(listener);
    }

    public void addAccessChangedListener(AccessChangedListener listener) {
        accessChangedListeners.add(listener);
    }

    public void removeAccessChangedListener(AccessChangedListener listener) {
        accessChangedListeners.remove(listener);
    }

    public void addForwardChangedListener(ForwardChangedListener listener) {
        forwardChangedListeners.add(listener);
    }

    public void removeForwardChangedListener(ForwardChangedListener listener) {
        forwardChangedListeners.remove(listener);
    }

    // HeartGuard change - notify of whitelist changes
    public void addWhitelistChangedListener(WhitelistChangedListener listener) {
        whitelistChangedListeners.add(listener);
    }

    public void removeWhitelistChangedListener(WhitelistChangedListener listener) {
        whitelistChangedListeners.remove(listener);
    }

    // HeartGuard change - notify of rule changes
    public void addRuleChangedListener(RuleChangedListener listener) {
        ruleChangedListeners.add(listener);
    }

    public void removeRuleChangedListener(RuleChangedListener listener) {
        ruleChangedListeners.remove(listener);
    }

    private void notifyLogChanged() {
        Message msg = handler.obtainMessage();
        msg.what = MSG_LOG;
        handler.sendMessage(msg);
    }

    private void notifyAccessChanged() {
        Message msg = handler.obtainMessage();
        msg.what = MSG_ACCESS;
        handler.sendMessage(msg);
    }

    private void notifyForwardChanged() {
        Message msg = handler.obtainMessage();
        msg.what = MSG_FORWARD;
        handler.sendMessage(msg);
    }

    // HeartGuard change - notify of whitelist changes
    private void notifyWhitelistChanged() {
        Message msg = handler.obtainMessage();
        msg.what = MSG_WHITELIST;
        handler.sendMessage(msg);
    }

    // HeartGuard change - notify of rule changes
    private void notifyRuleChanged() {
        Message msg = handler.obtainMessage();
        msg.what = MSG_RULE;
        handler.sendMessage(msg);
    }

    private static void handleChangedNotification(Message msg) {
        // Batch notifications
        try {
            // HeartGuard change - inform of whitelist changes first (so that we don't delay traffic)
            int sleep_time = 1000;
            if (msg.what == MSG_WHITELIST || handler.hasMessages(MSG_WHITELIST)) {
                handler.removeMessages(msg.what);
                for (WhitelistChangedListener listener : whitelistChangedListeners)
                    try {
                        listener.onChanged();
                    } catch (Throwable ex) {
                        Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                    }
                sleep_time = 100;
            }
            Thread.sleep(sleep_time);
            if ((msg.what != MSG_WHITELIST) && handler.hasMessages(msg.what))
                handler.removeMessages(msg.what);
        } catch (InterruptedException ignored) {
        }

        // Notify listeners
        if (msg.what == MSG_LOG) {
            for (LogChangedListener listener : logChangedListeners)
                try {
                    listener.onChanged();
                } catch (Throwable ex) {
                    Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                }

        } else if (msg.what == MSG_ACCESS) {
            for (AccessChangedListener listener : accessChangedListeners)
                try {
                    listener.onChanged();
                } catch (Throwable ex) {
                    Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                }

        } else if (msg.what == MSG_FORWARD) {
            for (ForwardChangedListener listener : forwardChangedListeners)
                try {
                    listener.onChanged();
                } catch (Throwable ex) {
                    Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                }
        } else if (msg.what == MSG_RULE) {
            for (RuleChangedListener listener : ruleChangedListeners)
                try {
                    listener.onChanged();
                } catch (Throwable ex) {
                    Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                }
        }
    }

    public interface LogChangedListener {
        void onChanged();
    }

    public interface AccessChangedListener {
        void onChanged();
    }

    public interface ForwardChangedListener {
        void onChanged();
    }

    // HeartGuard change - notify of whitelist changes
    public interface WhitelistChangedListener {
        void onChanged();
    }

    // HeartGuard change - notify of rule changes
    public interface RuleChangedListener {
        void onChanged();
    }

    // HeartGuard change - get cursor of enacted rules from the DB
    public Cursor getEnactedRules() {
        lock.readLock().lock();
        try {
            SQLiteDatabase db = this.getReadableDatabase();
            // There is a segmented index on uid
            // There is an index on block
            return db.query("rules", null, "enacted == 1", null, null, null, null);
        } finally {
            lock.readLock().unlock();
        }
    }

    public Map<Long, String> getEnactedRulesMap() {
        Map<Long, String> enacted_rules = new HashMap<>();

        try (Cursor cursor = dh.getEnactedRules()) {
            int col_ruletext = cursor.getColumnIndexOrThrow("ruletext");
            int col_id = cursor.getColumnIndexOrThrow("_id");

            while (cursor.moveToNext()) {
                enacted_rules.put(cursor.getLong(col_id), cursor.getString(col_ruletext));
            }
        }

        return enacted_rules;
    }

    // HeartGuard change - get cursor of pending rules
    public Cursor getPendingRules() {
        lock.readLock().lock();
        try {
            SQLiteDatabase db = this.getReadableDatabase();
            // There is a segmented index on uid
            // There is an index on block
            return db.query("rules", null, "enacted == 0", null, null, null, "enact_time ASC");
        } finally {
            lock.readLock().unlock();
        }
    }

    // HeartGuard change - get cursor of all rules
    public Cursor getAllRules() {
        lock.readLock().lock();
        try {
            SQLiteDatabase db = this.getReadableDatabase();
            // There is a segmented index on uid
            // There is an index on block
            return db.query("rules", null, "", null, null, null, "_id ASC");
        } finally {
            lock.readLock().unlock();
        }
    }

    // HeartGuard change - get cursor of all rules, sorted for the RulesList view
    public Cursor getAllRulesSorted() {
        lock.readLock().lock();
        try {
            SQLiteDatabase db = this.getReadableDatabase();

            String query = "SELECT * FROM ( SELECT * FROM rules WHERE enacted = 0 ORDER BY enact_time, major_category, minor_category, ruletext, _id )";
            query += " UNION ALL";
            query += " SELECT * FROM ( SELECT * FROM rules WHERE enacted = 1 ORDER BY major_category, minor_category, ruletext, _id )";
            return db.rawQuery(query, new String[]{});
        } finally {
            lock.readLock().unlock();
        }
    }

    // HeartGuard change - get rule by ruletext
    public Cursor getRuleMatchingRuletext(String ruletext) {
        lock.readLock().lock();
        try {
            SQLiteDatabase db = this.getReadableDatabase();
            // There is a segmented index on uid
            // There is an index on block
            return db.query("rules", null, "ruletext == ?", new String[]{ruletext}, null, null, "enact_time DESC");
        } finally {
            lock.readLock().unlock();
        }
    }

    // HeartGuard change - add new rule, enacted or not
    public void addNewRule(String ruletext, long create_time, long enact_time, int enacted, int major_category, int minor_category) {
        ContentValues cv = new ContentValues();
        cv.put("ruletext", ruletext);
        cv.put("create_time", create_time);
        cv.put("enact_time", enact_time);
        cv.put("enacted", enacted);
        cv.put("major_category", major_category);
        cv.put("minor_category", minor_category);

        lock.writeLock().lock();
        try {
            SQLiteDatabase db = this.getWritableDatabase();

            db.insertOrThrow("rules", null, cv);
        } finally {
            lock.writeLock().unlock();
        }

        notifyRuleChanged();
    }

    // HeartGuard change - set exact row to enacted
    public void setRuleEnacted(String ID, int enacted) {
        ContentValues cv = new ContentValues();
        cv.put("enacted", enacted);

        lock.writeLock().lock();
        try {
            SQLiteDatabase db = this.getWritableDatabase();

            db.update("rules", cv, "_id = ?", new String[]{ID});
        } finally {
            lock.writeLock().unlock();
        }

        notifyRuleChanged();
    }

    // HeartGuard change - update exact row with new CV
    public void updateRuleWithCV(String ID, ContentValues cv) {
        lock.writeLock().lock();
        try {
            SQLiteDatabase db = this.getWritableDatabase();

            db.update("rules", cv, "_id = ?", new String[]{ID});
        } finally {
            lock.writeLock().unlock();
        }
    }

    public void removeRulesById(Long[] ids) {
        lock.writeLock().lock();
        try {
            SQLiteDatabase db = this.getWritableDatabase();

            for (long id : ids) {
                db.delete("rules", "_id = ?", new String[]{Long.toString(id)});
            }
        } finally {
            lock.writeLock().unlock();
        }

        notifyRuleChanged();
    }

    public void setAccessPending(String ID, int pending) {
        ContentValues cv = new ContentValues();
        cv.put("pending_allow", pending);

        lock.writeLock().lock();
        try {
            SQLiteDatabase db = this.getWritableDatabase();

            db.update("access", cv, "ID = ?", new String[]{ID});
        } finally {
            lock.writeLock().unlock();
        }

        notifyAccessChanged();
    }
}
