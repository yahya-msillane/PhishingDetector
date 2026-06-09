package com.yahya.phishingdetector;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * UrlAnalyzer.java
 * Performs structured URL feature extraction for phishing detection.
 * Each feature contributes to the overall threat score.
 */
public class UrlAnalyzer {

    // ── Suspicious TLDs ──────────────────────────────────────────────────────
    private static final List<String> SUSPICIOUS_TLDS = Arrays.asList(
            ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".click",
            ".loan", ".work", ".party", ".review", ".science", ".stream"
    );

    // ── URL shorteners ────────────────────────────────────────────────────────
    private static final List<String> URL_SHORTENERS = Arrays.asList(
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
            "buff.ly", "adf.ly", "tiny.cc", "shorturl.at", "rb.gy", "cutt.ly"
    );

    // ── Phishing brand spoofs ─────────────────────────────────────────────────
    private static final List<String> BRAND_KEYWORDS = Arrays.asList(
            "paypa1", "paypai", "g00gle", "arnazon", "amaz0n", "faceb00k",
            "rn icrosoft", "micros0ft", "app1e", "netf1ix", "droptox"
    );

    // ── Suspicious path/query keywords ───────────────────────────────────────
    private static final List<String> PATH_KEYWORDS = Arrays.asList(
            "verify", "login", "signin", "account", "update", "secure",
            "banking", "confirm", "wallet", "reset", "password", "credential"
    );

    // ── Result container ─────────────────────────────────────────────────────
    public static class UrlAnalysisResult {
        public int score = 0;
        public List<String> flags = new ArrayList<>();
        public boolean isUrl = false;

        // Raw features (useful for ML model input later)
        public int urlLength;
        public int subdomainCount;
        public boolean hasIpAddress;
        public boolean usesHttps;
        public boolean isShortener;
        public boolean hasSuspiciousTld;
        public boolean hasBrandSpoof;
        public boolean hasHyphenInDomain;
        public int specialCharCount;
        public int digitCountInDomain;
        public boolean hasAtSymbol;
        public boolean hasDoubleSlash;
        public boolean hasRedirectParam;
    }

    // ── URL pattern ───────────────────────────────────────────────────────────
    private static final Pattern URL_PATTERN = Pattern.compile(
            "https?://[\\w\\-]+(\\.[\\w\\-]+)+([\\w\\-._~:/?#\\[\\]@!$&'()*+,;=%]*)?",
            Pattern.CASE_INSENSITIVE
    );

    private static final Pattern IP_PATTERN = Pattern.compile(
            "^(\\d{1,3}\\.){3}\\d{1,3}$"
    );

    // ─────────────────────────────────────────────────────────────────────────
    /**
     * Extracts all URLs from text, analyzes them, and returns a combined result.
     */
    public static UrlAnalysisResult analyzeText(String text) {
        UrlAnalysisResult combined = new UrlAnalysisResult();
        Matcher m = URL_PATTERN.matcher(text);

        while (m.find()) {
            UrlAnalysisResult r = analyzeUrl(m.group());
            combined.score = Math.min(100, combined.score + r.score);
            combined.flags.addAll(r.flags);
            combined.isUrl = true;
        }
        return combined;
    }

    /**
     * Analyzes a single URL and returns a scored result.
     */
    public static UrlAnalysisResult analyzeUrl(String rawUrl) {
        UrlAnalysisResult result = new UrlAnalysisResult();
        result.isUrl = true;

        String lower = rawUrl.toLowerCase().trim();
        URL parsed;
        try {
            parsed = new URL(rawUrl);
        } catch (MalformedURLException e) {
            result.flags.add("🔗 Malformed URL detected");
            result.score += 20;
            return result;
        }

        String host   = parsed.getHost() != null ? parsed.getHost().toLowerCase() : "";
        String path   = parsed.getPath() != null ? parsed.getPath().toLowerCase() : "";
        String query  = parsed.getQuery() != null ? parsed.getQuery().toLowerCase() : "";

        // 1. URL length
        result.urlLength = rawUrl.length();
        if (rawUrl.length() > 75) {
            result.flags.add("📏 Very long URL (" + rawUrl.length() + " chars)");
            result.score += 10;
        }
        if (rawUrl.length() > 100) {
            result.score += 10; // extra penalty
        }

        // 2. IP address as host
        result.hasIpAddress = IP_PATTERN.matcher(host).matches();
        if (result.hasIpAddress) {
            result.flags.add("🖥️ IP address used instead of domain");
            result.score += 25;
        }

        // 3. HTTPS check
        result.usesHttps = parsed.getProtocol().equalsIgnoreCase("https");
        if (!result.usesHttps) {
            result.flags.add("🔓 No HTTPS (insecure connection)");
            result.score += 15;
        }

        // 4. URL shortener
        result.isShortener = false;
        for (String shortener : URL_SHORTENERS) {
            if (host.contains(shortener)) {
                result.isShortener = true;
                result.flags.add("🔗 URL shortener detected (" + shortener + ")");
                result.score += 20;
                break;
            }
        }

        // 5. Suspicious TLD
        result.hasSuspiciousTld = false;
        for (String tld : SUSPICIOUS_TLDS) {
            if (host.endsWith(tld)) {
                result.hasSuspiciousTld = true;
                result.flags.add("🌐 Suspicious TLD (" + tld + ")");
                result.score += 20;
                break;
            }
        }

        // 6. Brand spoofing in hostname
        result.hasBrandSpoof = false;
        for (String brand : BRAND_KEYWORDS) {
            if (host.contains(brand)) {
                result.hasBrandSpoof = true;
                result.flags.add("🎭 Brand spoofing detected (" + brand + ")");
                result.score += 30;
                break;
            }
        }

        // 7. Hyphen count in domain
        String[] hostParts = host.split("\\.");
        String registrableDomain = hostParts.length >= 2
                ? hostParts[hostParts.length - 2]
                : host;
        result.hasHyphenInDomain = registrableDomain.contains("-");
        if (registrableDomain.chars().filter(c -> c == '-').count() >= 2) {
            result.flags.add("➖ Multiple hyphens in domain");
            result.score += 15;
        }

        // 8. Subdomain depth
        result.subdomainCount = Math.max(0, hostParts.length - 2);
        if (result.subdomainCount >= 3) {
            result.flags.add("🔀 Excessive subdomains (" + result.subdomainCount + " levels)");
            result.score += 15;
        }

        // 9. Digits in domain name
        result.digitCountInDomain = (int) registrableDomain.chars()
                .filter(Character::isDigit).count();
        if (result.digitCountInDomain >= 3) {
            result.flags.add("🔢 Many digits in domain name");
            result.score += 10;
        }

        // 10. @ symbol in URL (tricks browsers)
        result.hasAtSymbol = lower.contains("@");
        if (result.hasAtSymbol) {
            result.flags.add("🔵 @ symbol in URL (browser trick)");
            result.score += 25;
        }

        // 11. Double slash in path
        result.hasDoubleSlash = path.contains("//");
        if (result.hasDoubleSlash) {
            result.flags.add("⚡ Double slash in URL path");
            result.score += 10;
        }

        // 12. Redirect parameters
        result.hasRedirectParam = query.contains("redirect=")
                || query.contains("url=")
                || query.contains("goto=")
                || query.contains("link=");
        if (result.hasRedirectParam) {
            result.flags.add("↩️ Redirect parameter in URL");
            result.score += 15;
        }

        // 13. Suspicious path keywords
        for (String kw : PATH_KEYWORDS) {
            if (path.contains(kw) || query.contains(kw)) {
                result.flags.add("🔑 Suspicious path keyword: \"" + kw + "\"");
                result.score += 10;
                break; // one penalty per URL
            }
        }

        // 14. Special characters count
        result.specialCharCount = (int) lower.chars()
                .filter(c -> "!$%^&*(){}[]|<>?".indexOf(c) >= 0).count();
        if (result.specialCharCount > 5) {
            result.flags.add("❗ Many special characters in URL");
            result.score += 10;
        }

        result.score = Math.min(100, result.score);
        return result;
    }
}