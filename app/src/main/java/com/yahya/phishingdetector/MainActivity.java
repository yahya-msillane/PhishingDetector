package com.yahya.phishingdetector;

import android.content.Intent;
import android.graphics.Color;
import android.net.Uri;
import android.os.Bundle;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ListView;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.cardview.widget.CardView;
import androidx.core.content.FileProvider;

import java.io.File;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Locale;

public class MainActivity extends AppCompatActivity {

    private EditText inputText;
    private Button analyzeBtn, clearBtn, generateReportBtn;
    private TextView resultLabel, scoreText, mlScoreText;
    private CardView resultCard;
    private ListView historyList;
    private ProgressBar riskBar;

    private ArrayList<String> historyItems = new ArrayList<>();
    private ArrayAdapter<String> historyAdapter;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        bindViews();
        setupHistory();

        analyzeBtn.setOnClickListener(v -> analyzeText(inputText.getText().toString()));
        clearBtn.setOnClickListener(v -> {
            inputText.setText("");
            resultCard.setVisibility(View.GONE);
        });
        generateReportBtn.setOnClickListener(v -> generateHtmlReport());
    }

    private void bindViews() {
        inputText = findViewById(R.id.inputText);
        analyzeBtn = findViewById(R.id.analyzeBtn);
        clearBtn = findViewById(R.id.clearBtn);
        generateReportBtn = findViewById(R.id.generateReportBtn);
        resultLabel = findViewById(R.id.resultLabel);
        scoreText = findViewById(R.id.scoreText);
        mlScoreText = findViewById(R.id.mlScoreText);
        resultCard = findViewById(R.id.resultCard);
        historyList = findViewById(R.id.historyList);
        riskBar = findViewById(R.id.riskBar);
    }

    private void setupHistory() {
        historyAdapter = new ArrayAdapter<>(this, android.R.layout.simple_list_item_1, historyItems);
        historyList.setAdapter(historyAdapter);
    }

    private void analyzeText(String text) {
        if (text.trim().isEmpty()) {
            resultCard.setVisibility(View.VISIBLE);
            resultLabel.setText("⚠️ Please enter some text first");
            resultLabel.setTextColor(Color.WHITE);
            scoreText.setText("");
            return;
        }

        UrlAnalyzer.UrlAnalysisResult urlResult = UrlAnalyzer.analyzeText(text);
        PhishingMLClassifier.MLResult mlResult = PhishingMLClassifier.classify(text, urlResult);
        int ruleScore = computeRuleScore(text.toLowerCase());
        int urlScore = urlResult.isUrl ? urlResult.score : 0;
        int finalScore = (int) (mlResult.riskScore * 0.60f + urlScore * 0.30f + ruleScore * 0.10f);
        finalScore = Math.min(100, finalScore);

        displayResult(finalScore, text, mlResult, urlResult);
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

    private void displayResult(int score, String text,
                               PhishingMLClassifier.MLResult mlResult,
                               UrlAnalyzer.UrlAnalysisResult urlResult) {
        resultCard.setVisibility(View.VISIBLE);
        if (riskBar != null) riskBar.setProgress(score);

        String time = new SimpleDateFormat("HH:mm", Locale.getDefault()).format(new Date());
        String preview = text.length() > 30 ? text.substring(0, 30) + "..." : text;

        StringBuilder detail = new StringBuilder();
        if (!mlResult.topFeatures.isEmpty()) {
            detail.append("🤖 ML Signals:\n");
            for (String f : mlResult.topFeatures) detail.append("  ").append(f).append("\n");
            detail.append("\n");
        }
        if (urlResult.isUrl && !urlResult.flags.isEmpty()) {
            detail.append("🔗 URL Analysis:\n");
            for (String f : urlResult.flags) detail.append("  ").append(f).append("\n");
        }
        if (score == 0 && !urlResult.isUrl) detail.append("No suspicious patterns detected.");
        scoreText.setText(detail.toString().trim());

        if (mlScoreText != null) {
            mlScoreText.setText(String.format("🧠 ML confidence: %.1f%%  |  Risk score: %d/100",
                    mlResult.probability * 100, score));
        }

        String historyEntry;
        if (score == 0) {
            setResult("✅  SAFE", "#2ECC71", score);
            historyEntry = "✅ SAFE [" + time + "] — " + preview;
        } else if (score < 35) {
            setResult("🟡  LOW RISK — " + score + "/100", "#F1C40F", score);
            historyEntry = "🟡 LOW [" + time + "] — " + preview;
        } else if (score < 65) {
            setResult("🟠  MEDIUM RISK — " + score + "/100", "#E67E22", score);
            showAlert("⚠️ Medium Risk", "This message contains suspicious patterns.\nStay cautious.");
            historyEntry = "🟠 MEDIUM [" + time + "] — " + preview;
        } else {
            setResult("🔴  PHISHING DETECTED — " + score + "/100", "#E74C3C", score);
            showAlert("🚨 DANGER!", "This is likely a PHISHING attempt!\n\n• Do NOT click any links\n• Do NOT share personal information\n• Report to your bank / provider");
            historyEntry = "🔴 PHISHING [" + time + "] — " + preview;
        }

        historyItems.add(0, historyEntry);
        if (historyItems.size() > 50) historyItems.remove(historyItems.size() - 1);
        historyAdapter.notifyDataSetChanged();
    }

    private void setResult(String label, String hexColor, int score) {
        resultLabel.setText(label);
        resultLabel.setTextColor(Color.parseColor(hexColor));
        if (riskBar != null) riskBar.setProgress(score);
    }

    private void showAlert(String title, String message) {
        new AlertDialog.Builder(this)
                .setTitle(title)
                .setMessage(message)
                .setPositiveButton("OK, I understand", (d, w) -> d.dismiss())
                .setCancelable(false)
                .show();
    }

    private void generateHtmlReport() {
        AlertDialog loading = new AlertDialog.Builder(this)
                .setTitle("Generating report")
                .setMessage("Analyzing dataset messages...\nPlease wait.")
                .setCancelable(false)
                .create();
        loading.show();

        new Thread(() -> {
            try {
                ReportGenerator rg = new ReportGenerator(this);
                rg.loadAndAnalyzeDataset();
                File htmlFile = rg.generateHtmlReport();

                runOnUiThread(() -> {
                    loading.dismiss();
                    new AlertDialog.Builder(this)
                            .setTitle("Report ready")
                            .setMessage("HTML report created.\nOpen it in your browser?")
                            .setPositiveButton("Open", (d, w) -> openHtmlReport(htmlFile))
                            .setNegativeButton("Cancel", null)
                            .show();
                });
            } catch (Exception e) {
                e.printStackTrace();
                runOnUiThread(() -> {
                    loading.dismiss();
                    Toast.makeText(this, "Error: " + e.getMessage(), Toast.LENGTH_LONG).show();
                });
            }
        }).start();
    }

    private void openHtmlReport(File htmlFile) {
        Uri uri = FileProvider.getUriForFile(this, getPackageName() + ".provider", htmlFile);
        Intent intent = new Intent(Intent.ACTION_VIEW);
        intent.setDataAndType(uri, "text/html");
        intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        startActivity(intent);
    }
}