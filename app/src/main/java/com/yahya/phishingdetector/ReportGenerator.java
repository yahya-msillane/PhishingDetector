package com.yahya.phishingdetector;

import android.content.Context;
import android.content.res.AssetManager;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

public class ReportGenerator {

    private Context context;
    private List<PhishingRecord> records = new ArrayList<>();

    public ReportGenerator(Context context) {
        this.context = context;
    }

    public void loadAndAnalyzeDataset() throws Exception {
        AssetManager assetManager = context.getAssets();
        BufferedReader reader = new BufferedReader(new InputStreamReader(assetManager.open("phishing_dataset.csv")));
        String line;
        boolean firstLine = true;
        while ((line = reader.readLine()) != null) {
            if (firstLine) { firstLine = false; continue; }
            if (line.trim().isEmpty()) continue;

            // Parse CSV line respecting quotes
            List<String> parts = parseCsvLine(line);
            if (parts.size() < 4) continue;

            String id = parts.get(0);
            String text = parts.get(1);
            // Remove surrounding quotes if present
            if (text.startsWith("\"") && text.endsWith("\"")) {
                text = text.substring(1, text.length() - 1);
            }
            int urlPresent = Integer.parseInt(parts.get(2).trim());
            String trueLabel = parts.get(3).trim();

            // Analyze with your existing engine
            UrlAnalyzer.UrlAnalysisResult urlResult = UrlAnalyzer.analyzeText(text);
            PhishingMLClassifier.MLResult mlResult = PhishingMLClassifier.classify(text, urlResult);
            int ruleScore = computeRuleScore(text.toLowerCase());
            int urlScore = urlResult.isUrl ? urlResult.score : 0;
            int finalScore = (int) (mlResult.riskScore * 0.60f + urlScore * 0.30f + ruleScore * 0.10f);
            finalScore = Math.min(100, finalScore);
            boolean detected = finalScore >= 65;

            records.add(new PhishingRecord(text, trueLabel, detected, finalScore, urlResult.flags));
        }
        reader.close();
    }

    // CSV parser that respects quotes
    private List<String> parseCsvLine(String line) {
        List<String> result = new ArrayList<>();
        boolean inQuotes = false;
        StringBuilder current = new StringBuilder();
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (c == '"') {
                inQuotes = !inQuotes;
            } else if (c == ',' && !inQuotes) {
                result.add(current.toString());
                current.setLength(0);
            } else {
                current.append(c);
            }
        }
        result.add(current.toString());
        return result;
    }

    private int computeRuleScore(String lower) {
        String[] keywords = {
                "click here", "verify your account", "urgent", "you have won",
                "free prize", "claim now", "password expired", "suspended",
                "confirm your identity", "limited time", "act now", "dear customer",
                "bank account", "credit card", "otp", "login immediately",
                "unusual activity"
        };
        String[] domains = {
                "free-money", "win-prize", "click4prize", "verify-account",
                "secure-login", "account-suspended", ".xyz", ".tk", ".ml", ".ga"
        };
        int score = 0;
        for (String kw : keywords) if (lower.contains(kw)) score += 15;
        for (String d : domains) if (lower.contains(d)) score += 20;
        return Math.min(100, score);
    }

    public File generateHtmlReport() throws Exception {
        File reportDir = new File(context.getExternalFilesDir(null), "reports");
        if (!reportDir.exists()) reportDir.mkdirs();

        String timeStamp = new SimpleDateFormat("yyyyMMdd_HHmmss", Locale.getDefault()).format(new Date());
        File htmlFile = new File(reportDir, "phishing_report_" + timeStamp + ".html");

        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html><html><head><meta charset='UTF-8'><title>Phishing Detection Report</title>");
        html.append("<style>body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; } ");
        html.append(".container { max-width: 1200px; margin: auto; background: white; padding: 20px; border-radius: 10px; } ");
        html.append("h1 { color: #E74C3C; } ");
        html.append(".stat { background: #f0f0f0; padding: 10px; margin: 10px 0; border-radius: 8px; } ");
        html.append(".record { border: 1px solid #ccc; margin: 10px 0; padding: 10px; border-radius: 5px; } ");
        html.append(".phishing { background: #ffe6e6; border-left: 5px solid #E74C3C; } ");
        html.append(".safe { background: #e6ffe6; border-left: 5px solid #2ECC71; } ");
        html.append("</style></head><body><div class='container'>");

        html.append("<h1>📱 Phishing Detector - Analysis Report</h1>");
        html.append("<p>Generated on: ").append(new Date().toString()).append("</p>");

        // Statistics
        int total = records.size();
        int detected = 0;
        int falsePos = 0, falseNeg = 0;
        for (PhishingRecord r : records) {
            if (r.detected) detected++;
            if (r.detected && r.trueLabel.equalsIgnoreCase("safe")) falsePos++;
            if (!r.detected && r.trueLabel.equalsIgnoreCase("phishing")) falseNeg++;
        }
        html.append("<div class='stat'><h2>📊 Statistics</h2>");
        html.append("<p><strong>Total messages analyzed:</strong> ").append(total).append("</p>");
        html.append("<p><strong>Phishing detected:</strong> ").append(detected).append("</p>");
        html.append("<p><strong>False Positives (safe flagged as phishing):</strong> ").append(falsePos).append("</p>");
        html.append("<p><strong>False Negatives (phishing missed):</strong> ").append(falseNeg).append("</p>");
        double accuracy = 100.0 * (total - falsePos - falseNeg) / total;
        html.append("<p><strong>Accuracy:</strong> ").append(String.format("%.2f%%", accuracy)).append("</p>");
        html.append("</div>");

        html.append("<h2>📋 Detailed Results</h2>");
        for (int i = 0; i < records.size(); i++) {
            PhishingRecord r = records.get(i);
            String cls = r.detected ? "phishing" : "safe";
            html.append("<div class='record ").append(cls).append("'>");
            html.append("<strong>").append(i+1).append(". </strong>");
            html.append("<strong>Detection:</strong> ").append(r.detected ? "⚠️ PHISHING" : "✅ SAFE");
            html.append(" | <strong>Score:</strong> ").append(r.score);
            html.append(" | <strong>True label:</strong> ").append(r.trueLabel);
            html.append("<br><strong>Message:</strong> ").append(escapeHtml(r.text));
            if (!r.flags.isEmpty()) {
                String flagsStr = String.join(", ", r.flags);
                if (flagsStr.length() > 200) flagsStr = flagsStr.substring(0, 200) + "...";
                html.append("<br><strong>Flags:</strong> ").append(escapeHtml(flagsStr));
            }
            html.append("</div>");
        }

        html.append("</div></body></html>");

        FileOutputStream fos = new FileOutputStream(htmlFile);
        fos.write(html.toString().getBytes());
        fos.close();
        return htmlFile;
    }

    private String escapeHtml(String s) {
        return s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;");
    }

    static class PhishingRecord {
        String text, trueLabel;
        boolean detected;
        int score;
        List<String> flags;
        PhishingRecord(String text, String trueLabel, boolean detected, int score, List<String> flags) {
            this.text = text; this.trueLabel = trueLabel; this.detected = detected; this.score = score; this.flags = flags;
        }
    }
}