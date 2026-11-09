package netanomaly.io;

import netanomaly.model.Conn;
import netanomaly.model.DnsQuery;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.function.Function;
import java.util.zip.GZIPInputStream;

/**
 * Reads Zeek logs in the default tab-separated (TSV) format.
 *
 * Zeek TSV files start with header lines like:
 *   #separator \x09
 *   #fields    ts  uid  id.orig_h  id.orig_p ...
 *   #types     time string addr port ...
 * The "#fields" line tells us which column is which, so this works even if
 * your Zeek version adds or reorders columns. "-" means "no value".
 * Plain .log and rotated .log.gz files are both supported.
 */
public final class ZeekReader {

    private ZeekReader() {}

    public static List<Conn> readConn(Path file) throws IOException {
        return read(file, row -> new Conn(
                row.dbl("ts"),
                row.str("uid"),
                row.str("id.orig_h"),
                row.integer("id.orig_p"),
                row.str("id.resp_h"),
                row.integer("id.resp_p"),
                row.str("proto"),
                row.str("service"),
                row.dbl("duration"),
                row.lng("orig_bytes"),
                row.lng("resp_bytes"),
                row.str("conn_state"),
                row.lng("orig_pkts"),
                row.lng("resp_pkts")));
    }

    public static List<DnsQuery> readDns(Path file) throws IOException {
        List<DnsQuery> all = read(file, row -> new DnsQuery(
                row.dbl("ts"),
                row.str("uid"),
                row.str("id.orig_h"),
                row.str("id.resp_h"),
                row.str("query"),
                row.str("qtype_name"),
                row.str("rcode_name")));
        all.removeIf(q -> q.query().equals("-") || q.query().isBlank());
        return all;
    }

    private static <T> List<T> read(Path file, Function<Row, T> mapper) throws IOException {
        List<T> out = new ArrayList<>();
        Map<String, Integer> cols = null;
        int lineNo = 0, skipped = 0;
        try (BufferedReader br = open(file)) {
            String line;
            while ((line = br.readLine()) != null) {
                lineNo++;
                if (line.startsWith("#fields")) {
                    String[] names = line.split("\t");
                    cols = new HashMap<>();
                    for (int i = 1; i < names.length; i++) cols.put(names[i], i - 1);
                    continue;
                }
                if (line.startsWith("#") || line.isBlank()) continue;
                if (line.startsWith("{")) {
                    throw new IOException(file + " looks like JSON. Re-run Zeek without the JSON "
                            + "option (or with LogAscii::use_json=F) to get TSV logs.");
                }
                if (cols == null) throw new IOException(file + " has no #fields header - is it a Zeek log?");
                try {
                    out.add(mapper.apply(new Row(line.split("\t", -1), cols)));
                } catch (RuntimeException e) {
                    skipped++; // malformed row: skip it instead of crashing the whole run
                }
            }
        }
        if (skipped > 0) System.err.printf("  (skipped %d malformed lines in %s)%n", skipped, file);
        return out;
    }

    private static BufferedReader open(Path file) throws IOException {
        var in = Files.newInputStream(file);
        if (file.toString().endsWith(".gz")) in = new GZIPInputStream(in);
        return new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
    }

    /** Helper for pulling typed values out of one TSV row by column name. */
    private record Row(String[] values, Map<String, Integer> cols) {
        String str(String name) {
            Integer i = cols.get(name);
            if (i == null || i >= values.length) return "-";
            return values[i];
        }
        boolean empty(String v) { return v.equals("-") || v.equals("(empty)") || v.isEmpty(); }
        double dbl(String name) { String v = str(name); return empty(v) ? 0.0 : Double.parseDouble(v); }
        long lng(String name)   { String v = str(name); return empty(v) ? 0L : Long.parseLong(v); }
        int integer(String name){ String v = str(name); return empty(v) ? 0 : Integer.parseInt(v); }
    }
}
