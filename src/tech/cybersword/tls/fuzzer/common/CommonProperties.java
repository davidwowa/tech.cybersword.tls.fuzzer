package tech.cybersword.tls.fuzzer.common;

import java.util.logging.Level;
import java.util.logging.Logger;

import tech.cybersword.tls.fuzzer.util.LoggerUtil;
import tech.cybersword.tls.fuzzer.util.PropertyReader;

public class CommonProperties {

    private static final Logger logger = LoggerUtil.getLogger(CommonProperties.class.getName());

    private static String tlsHost;
    private static int tlsPort;
    private static int amountTLSRequests;
    private static int threadsAmount;
    private static int requestTimeout;
    private static boolean browserDashboardEnabled;
    private static int browserDashboardPort;
    private static boolean browserDashboardHttpsEnabled;
    private static String browserDashboardKeyStorePath;
    private static String browserDashboardKeyStorePassword;

    private static int randomMinArraySize;
    private static int randomMaxArraySize;
    private static int randomArraySize;

    private static String path = "tech.cybersword.tls.fuzzer.properties";

    private static CommonProperties instance;

    private CommonProperties() {
        init();
    }

    public static CommonProperties getInstance() {
        if (null == instance) {
            instance = new CommonProperties();
        }
        return instance;
    }

    private void init() {
        try {
            if (logger.isLoggable(Level.INFO)) {
                logger.info(String.format("Load configurations from %s", path));
            }

            PropertyReader reader = new PropertyReader(path);

            setTlsHost(reader.getProperty("tls.host"));
            setTlsPort(Integer.valueOf(reader.getProperty("tls.port")));
            setAmountTLSRequests(Integer.valueOf(reader.getProperty("tls.amountTLSRequests")));
            setThreadsAmount(Integer.valueOf(reader.getProperty("tls.threadsAmount")));
            setRequestTimeout(Integer.valueOf(reader.getProperty("tls.requestTimeout")));
            setBrowserDashboardEnabled(Boolean.parseBoolean(reader.getProperty("dashboard.browser.enabled")));
            setBrowserDashboardPort(Integer.valueOf(reader.getProperty("dashboard.browser.port")));
            setBrowserDashboardHttpsEnabled(Boolean.parseBoolean(reader.getProperty("dashboard.browser.https.enabled")));
            setBrowserDashboardKeyStorePath(reader.getProperty("dashboard.browser.https.keystore"));
            setBrowserDashboardKeyStorePassword(reader.getProperty("dashboard.browser.https.keystorePassword"));
            setRandomArraySize(Integer.valueOf(reader.getProperty("data.random.arraySize")));
            setRandomMaxArraySize(Integer.valueOf(reader.getProperty("data.random.maxSizeArray")));
            setRandomMinArraySize(Integer.valueOf(reader.getProperty("data.random.minSizeArray")));

            if (logger.isLoggable(Level.INFO)) {
                logger.info(String.format("Load configurations from %s", path));
            }
        } catch (Exception e) {
            if (logger.isLoggable(Level.SEVERE)) {
                logger.log(Level.SEVERE, String.format("Error by loading configurations from %s", path));
            }
            e.printStackTrace();
        }
    }

    public static String getTlsHost() {
        return tlsHost;
    }

    public static void setTlsHost(String tlsHost) {
        CommonProperties.tlsHost = tlsHost;
    }

    public static int getTlsPort() {
        return tlsPort;
    }

    public static void setTlsPort(int tlsPort) {
        CommonProperties.tlsPort = tlsPort;
    }

    public static int getAmountTLSRequests() {
        return amountTLSRequests;
    }

    public static void setAmountTLSRequests(int amountTLSRequests) {
        CommonProperties.amountTLSRequests = amountTLSRequests;
    }

    public static int getThreadsAmount() {
        return threadsAmount;
    }

    public static void setThreadsAmount(int threadsAmount) {
        CommonProperties.threadsAmount = threadsAmount;
    }

    public static int getRequestTimeout() {
        return requestTimeout;
    }

    public static void setRequestTimeout(int requestTimeout) {
        CommonProperties.requestTimeout = requestTimeout;
    }

    public static int getRandomMinArraySize() {
        return randomMinArraySize;
    }

    public static void setRandomMinArraySize(int randomMinArraySize) {
        CommonProperties.randomMinArraySize = randomMinArraySize;
    }

    public static int getRandomMaxArraySize() {
        return randomMaxArraySize;
    }

    public static void setRandomMaxArraySize(int randomMaxArraySize) {
        CommonProperties.randomMaxArraySize = randomMaxArraySize;
    }

    public static int getRandomArraySize() {
        return randomArraySize;
    }

    public static void setRandomArraySize(int randomArraySize) {
        CommonProperties.randomArraySize = randomArraySize;
    }

    public static boolean isBrowserDashboardEnabled() {
        return browserDashboardEnabled;
    }

    public static void setBrowserDashboardEnabled(boolean browserDashboardEnabled) {
        CommonProperties.browserDashboardEnabled = browserDashboardEnabled;
    }

    public static int getBrowserDashboardPort() {
        return browserDashboardPort;
    }

    public static void setBrowserDashboardPort(int browserDashboardPort) {
        CommonProperties.browserDashboardPort = browserDashboardPort;
    }

    public static boolean isBrowserDashboardHttpsEnabled() {
        return browserDashboardHttpsEnabled;
    }

    public static void setBrowserDashboardHttpsEnabled(boolean browserDashboardHttpsEnabled) {
        CommonProperties.browserDashboardHttpsEnabled = browserDashboardHttpsEnabled;
    }

    public static String getBrowserDashboardKeyStorePath() {
        return browserDashboardKeyStorePath;
    }

    public static void setBrowserDashboardKeyStorePath(String browserDashboardKeyStorePath) {
        CommonProperties.browserDashboardKeyStorePath = browserDashboardKeyStorePath;
    }

    public static String getBrowserDashboardKeyStorePassword() {
        return browserDashboardKeyStorePassword;
    }

    public static void setBrowserDashboardKeyStorePassword(String browserDashboardKeyStorePassword) {
        CommonProperties.browserDashboardKeyStorePassword = browserDashboardKeyStorePassword;
    }

}
