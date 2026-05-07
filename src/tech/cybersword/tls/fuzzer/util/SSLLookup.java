package tech.cybersword.tls.fuzzer.util;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class SSLLookup {
	private static final Logger logger = LoggerUtil.getLogger(SSLLookup.class.getName());

    public static void main(String[] args) {
        String hostname = "google.com"; // Replace with your target hostname
        int port = 443; // Standard HTTPS port

        System.out.println("SSL/TLS version for " + hostname + ": " + getSSLVersion(hostname, port));
    }

    public static String getSSLVersion(String hostname, int port) {
        try (Socket socket = SSLSocketFactory.getDefault().createSocket()) {
            socket.connect(new InetSocketAddress(hostname, port));
            SSLSocket sslSocket = (SSLSocket) socket;

            sslSocket.startHandshake();

            return sslSocket.getSession().getProtocol();
		} catch (IOException e) {
			logger.log(Level.WARNING, "Failed to retrieve SSL/TLS version from " + hostname + ":" + port, e);
            return "Failed to retrieve SSL/TLS version";
        }
    }
}
